import base64
import hashlib
import secrets
import time
from typing import Dict, Any, Optional
import html
from urllib.parse import urlencode

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
from pydantic import BaseModel


app = FastAPI()

# For local testing
ISSUER = "https://knickers-curator-vista.ngrok-free.dev"
MCP_RESOURCE = "https://knickers-curator-vista.ngrok-free.dev/mcp"

SPRING_MCP_URL = "http://localhost:8000/mcp"

# In-memory stores. For demo only.
clients: Dict[str, Dict[str, Any]] = {}
auth_codes: Dict[str, Dict[str, Any]] = {}
access_tokens: Dict[str, Dict[str, Any]] = {}
def now() -> int:
    return int(time.time())
clients["vscode-local"] = {

    "client_id": "vscode-local",

    "redirect_uris": [],

    "client_name": "VS Code MCP Client",

    "created_at": now(),

}



def pkce_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def bearer_401() -> JSONResponse:
    response = JSONResponse(
        status_code=401,
        content={
            "error": "unauthorized",
            "error_description": "Missing or invalid bearer token"
        },
    )
    response.headers[
        "WWW-Authenticate"
    ] = f'Bearer resource_metadata="{ISSUER}/.well-known/oauth-protected-resource"'
    return response


def get_bearer_token(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization")
    if not auth:
        return None
    if not auth.lower().startswith("bearer "):
        return None
    return auth.split(" ", 1)[1].strip()


def validate_token(request: Request) -> Dict[str, Any]:
    token = get_bearer_token(request)
    if not token:
        raise HTTPException(status_code=401)

    record = access_tokens.get(token)
    if not record:
        raise HTTPException(status_code=401)

    if record["expires_at"] < now():
        raise HTTPException(status_code=401)

    return record


@app.exception_handler(HTTPException)
async def auth_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == 401:
        return bearer_401()
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

def is_allowed_redirect_uri(client: dict, redirect_uri: str) -> bool:
    if redirect_uri in client.get("redirect_uris", []):
        return True

    # VS Code usually uses localhost / 127.0.0.1 callback ports.
    # Dev only. Do not use this in production.
    if redirect_uri.startswith("http://127.0.0.1:") or redirect_uri.startswith("http://localhost:"):
        return True

    return False


# ----------------------------------------------------------------------
# 1. MCP Protected Resource Metadata - RFC 9728 style
# ----------------------------------------------------------------------
@app.get("/.well-known/oauth-protected-resource")
async def protected_resource_metadata():
    return {
        "resource": MCP_RESOURCE,
        "authorization_servers": [ISSUER],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["mcp:tools"],
    }


# Some clients may try resource-specific variant.
@app.get("/.well-known/oauth-protected-resource/mcp")
async def protected_resource_metadata_mcp():
    return await protected_resource_metadata()


# ----------------------------------------------------------------------
# 2. OAuth Authorization Server Metadata - RFC 8414 style
# ----------------------------------------------------------------------
@app.get("/.well-known/oauth-authorization-server")
async def authorization_server_metadata():
    print(f"Metadata request received, clients={clients}")
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/oauth/authorize",
        "token_endpoint": f"{ISSUER}/oauth/token",
        "registration_endpoint": f"{ISSUER}/oauth/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["mcp:tools"],
    }



# Some clients may ask OIDC-style path.
@app.get("/.well-known/openid-configuration")
async def openid_configuration():
    return await authorization_server_metadata()


# ----------------------------------------------------------------------
# 3. Dynamic Client Registration
# ----------------------------------------------------------------------
@app.post("/oauth/register")
async def register_client(request: Request):
    body = await request.json()

    redirect_uris = body.get("redirect_uris", [])
    if not redirect_uris:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_client_metadata", "error_description": "redirect_uris required"},
        )

    client_id = "client_" + secrets.token_urlsafe(16)

    clients[client_id] = {
        "client_id": client_id,
        "redirect_uris": redirect_uris,
        "client_name": body.get("client_name", "mcp-client"),
        "created_at": now(),
    }

    return {
        "client_id": client_id,
        "client_id_issued_at": now(),
        "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }


# ----------------------------------------------------------------------
# 4. Authorization endpoint
# ----------------------------------------------------------------------
@app.get("/oauth/authorize")
async def authorize(
    response_type: str,
    client_id: str,
    redirect_uri: str,
    state: Optional[str] = None,
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = None,
    scope: Optional[str] = "mcp:tools",
    resource: Optional[str] = None,
):
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Only response_type=code supported")

    print(f"Authorization request for client_id={client_id}, clients={clients}")
    client = clients.get(client_id)
    if not client:
        client = client_id
        raise HTTPException(status_code=400, detail="Unknown client_id")

    if redirect_uri not in client["redirect_uris"]:
        raise HTTPException(status_code=400, detail="redirect_uri not registered")

    if code_challenge_method != "S256":
        raise HTTPException(status_code=400, detail="Only S256 PKCE supported")

    if not code_challenge:
        raise HTTPException(status_code=400, detail="code_challenge required")
    
    safe_state = html.escape(state or "", quote=True)

    # Demo login screen. In production, this is Cognito Hosted UI or your SSO.
    html_page = f"""
    <html>
      <body style="font-family: sans-serif; max-width: 700px; margin: 40px auto;">
        <h2>Demo MCP Authorization Server</h2>
        <p>Client <b>{client_id}</b> is requesting access to your MCP tools.</p>
        <p>Scope: <code>{scope}</code></p>
        <form method="post" action="/oauth/approve">
          <input type="hidden" name="client_id" value="{client_id}" />
          <input type="hidden" name="redirect_uri" value="{redirect_uri}" />
          <input type="hidden" name="state" value="{safe_state}" />
          <input type="hidden" name="code_challenge" value="{code_challenge}" />
          <input type="hidden" name="code_challenge_method" value="{code_challenge_method}" />
          <input type="hidden" name="scope" value="{scope or ''}" />
          <input type="hidden" name="resource" value="{resource or ''}" />

          <label>User:</label>
          <input name="username" value="jainish" />
          <br/><br/>
          <button type="submit">Approve</button>
        </form>
      </body>
    </html>
    """
    return HTMLResponse(html_page)


@app.post("/oauth/approve")
async def approve(
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    state: str = Form(""),
    code_challenge: str = Form(...),
    code_challenge_method: str = Form(...),
    scope: str = Form("mcp:tools"),
    resource: str = Form(""),
    username: str = Form("jainish"),
):
    code = "code_" + secrets.token_urlsafe(24)

    auth_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "scope": scope,
        "resource": resource,
        "username": username,
        "expires_at": now() + 300,
        "used": False,
    }

    separator = "&" if "?" in redirect_uri else "?"
    location = f"{redirect_uri}{separator}code={code}"
    if state:
        location += f"&state={state}"

    # print(f"Issued code {code} for client {client_id}, user {username}, scope {scope}, resource {resource}")
    # print(f"Redirecting to: {location}")

    query_params = {"code": code}
    if state:
        query_params["state"] = state

    separator = "&" if "?" in redirect_uri else "?"
    location = redirect_uri + separator + urlencode(query_params)

    print("REDIRECT location:", location)

    return RedirectResponse(url=location, status_code=302)


# ----------------------------------------------------------------------
# 5. Token endpoint
# ----------------------------------------------------------------------
@app.post("/oauth/token")
async def token(
    grant_type: str = Form(...),
    code: str = Form(...),
    redirect_uri: str = Form(...),
    client_id: str = Form(...),
    code_verifier: str = Form(...),
    resource: Optional[str] = Form(None),
):
    if grant_type != "authorization_code":
        return JSONResponse(status_code=400, content={"error": "unsupported_grant_type"})

    record = auth_codes.get(code)
    if not record:
        return JSONResponse(status_code=400, content={"error": "invalid_grant"})

    if record["used"]:
        return JSONResponse(status_code=400, content={"error": "invalid_grant", "error_description": "code already used"})

    if record["expires_at"] < now():
        return JSONResponse(status_code=400, content={"error": "invalid_grant", "error_description": "code expired"})

    if record["client_id"] != client_id:
        return JSONResponse(status_code=400, content={"error": "invalid_grant", "error_description": "client mismatch"})

    if record["redirect_uri"] != redirect_uri:
        return JSONResponse(status_code=400, content={"error": "invalid_grant", "error_description": "redirect_uri mismatch"})

    expected_challenge = record["code_challenge"]
    actual_challenge = pkce_s256(code_verifier)

    if actual_challenge != expected_challenge:
        return JSONResponse(status_code=400, content={"error": "invalid_grant", "error_description": "PKCE verification failed"})

    record["used"] = True

    access_token = "at_" + secrets.token_urlsafe(32)
    refresh_token = "rt_" + secrets.token_urlsafe(32)

    access_tokens[access_token] = {
        "client_id": client_id,
        "username": record["username"],
        "scope": record["scope"],
        "resource": resource or record.get("resource") or MCP_RESOURCE,
        "expires_at": now() + 3600,
    }

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": refresh_token,
        "scope": record["scope"],
    }


# ----------------------------------------------------------------------
# 6. MCP endpoint
# ----------------------------------------------------------------------
import httpx
from fastapi import Response

@app.post("/mcp")
async def mcp(request: Request):
    try:
        token_record = validate_token(request)
    except HTTPException:
        return bearer_401()

    body = await request.body()

    headers = {
        "Content-Type": request.headers.get("content-type", "application/json"),
        "Accept": request.headers.get("accept", "application/json, text/event-stream"),
    }

    # Optional: pass user identity to Spring MCP server
    headers["X-Authenticated-User"] = token_record["username"]
    headers["X-Client-Id"] = token_record["client_id"]
    headers["X-Scope"] = token_record["scope"]

    async with httpx.AsyncClient(timeout=60.0) as client:
        spring_response = await client.post(
            SPRING_MCP_URL,
            content=body,
            headers=headers,
        )

    return Response(
        content=spring_response.content,
        status_code=spring_response.status_code,
        media_type=spring_response.headers.get("content-type", "application/json"),
    )


@app.get("/")
async def home():
    return {
        "message": "MCP OAuth local demo running",
        "mcp": MCP_RESOURCE,
        "protected_resource_metadata": f"{ISSUER}/.well-known/oauth-protected-resource",
        "authorization_server_metadata": f"{ISSUER}/.well-known/oauth-authorization-server",
    }