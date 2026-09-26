import json, sys
from client import IndirectPromptInjectionSanitizerClient

def handle_mcp_request(payload):
    method = payload.get("method")
    req_id = payload.get("id", 1)
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"protocolVersion": "2024-11-05", "serverInfo": {"name": "indirect-prompt-injection-sanitizer", "version": "1.0.0"}}}
    elif method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": [{"name": "sanitize_untrusted_context", "description": "Scans untrusted web and document context for indirect prompt injection and neutralizes threats."}]}}
    elif method == "tools/call":
        client = IndirectPromptInjectionSanitizerClient()
        res = client.sanitize_untrusted_context()
        return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}}
    return {"jsonrpc": "2.0", "id": req_id, "result": {"status": "ACTIVE"}}

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print(json.dumps(handle_mcp_request({"method": "tools/list"})))
    else:
        client = IndirectPromptInjectionSanitizerClient()
        print(json.dumps(client.sanitize_untrusted_context(), indent=2))
