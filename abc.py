Last login: Sat Jun  6 18:40:52 on ttys006
(base) jainishshah@Jainishs-MacBook-Air ~ % ssh -i mcp-auth-gateway-dev-key-pair.pem -L 4040:localhost:4040 ec2-user@107.23.18.246
Warning: Identity file mcp-auth-gateway-dev-key-pair.pem not accessible: No such file or directory.
   ,     #_
   ~\_  ####_        Amazon Linux 2023
  ~~  \_#####\
  ~~     \###|
  ~~       \#/ ___   https://aws.amazon.com/linux/amazon-linux-2023
   ~~       V~' '->
    ~~~         /
      ~~._.   _/
         _/ _/
       _/m/'
Last login: Sat Jun  6 23:09:26 2026 from 98.109.151.171
[ec2-user@ip-172-31-39-216 ~]$ ls
mcp-gateway  ngrok.tgz
[ec2-user@ip-172-31-39-216 ~]$ cd mcp-gateway/
[ec2-user@ip-172-31-39-216 mcp-gateway]$ ls
__pycache__  main.py  requirements.txt
[ec2-user@ip-172-31-39-216 mcp-gateway]$ nano main.py































  GNU nano 8.3                                                                           main.py                                                                           Modified  
    if request.method == "GET":
        # For now, make GET valid but simple.
        # Later, if client expects SSE GET stream, wire streaming handling here.
        return {
            "status": "authenticated",
            "message": "MCP gateway is ready. Use POST /mcp for JSON-RPC."
        }

    body_bytes = await request.body()

    try:
        # AgentCore Runtime expects a payload.
        # Check exact parameter names with your installed boto3 version if needed.
        response = agentcore.invoke_agent_runtime(
            agentRuntimeArn=AGENTCORE_RUNTIME_ARN,
            qualifier=AGENTCORE_QUALIFIER,
            payload=body_bytes,
            contentType=request.headers.get("content-type", "application/json"),
            accept=request.headers.get("accept", "application/json, text/event-stream"),
        )

	# Boto3 response shape may return a stream-like object.
        runtime_body = response.get("response") or response.get("body") or response.get("payload")

        if hasattr(runtime_body, "read"):
            data = runtime_body.read()
        elif isinstance(runtime_body, (bytes, bytearray)):
            data = runtime_body
        else:
            data = json.dumps(runtime_body or {}).encode("utf-8")

        return Response(
            content=data,
            status_code=200,
            media_type=response.get("contentType", "application/json"),
        )

    except Exception as e:
        return JSONResponse(
            status_code=502,
            content={
                "error": "agentcore_invocation_failed",
                "message": str(e)
            }
	)