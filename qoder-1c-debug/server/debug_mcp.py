"""Тонкий stdio-транспорт над mcp_core — для проверки инструментов без Qoder.

Re-shoot: printf '%s\n' '<json-rpc>' ... | python qoder-1c-debug/server/debug_mcp.py

Плагин использует HTTP-вариант (debug_mcp_http.py): stdio Qoder на этой машине ещё не
проверен, а HTTP-серверы в плагинах уже работают (1c-syntax-helper, delphi-mcp).
"""
import json
import sys

import mcp_core as core

if hasattr(sys.stdin, "reconfigure"):
    # Windows иначе болтает stdio в cp866, и кириллица доходит до клиента кашей.
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")


def dispatch(request):
    method = request.get("method")
    params = request.get("params") or {}
    if method == "initialize":
        return {"protocolVersion": core.PROTOCOL_VERSION,
                "capabilities": {"tools": {}}, "serverInfo": core.SERVER_INFO}
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": core.TOOLS}
    if method == "tools/call":
        try:
            value = core.call(params.get("name"), params.get("arguments") or {})
            return {"content": [{"type": "text",
                                 "text": json.dumps(value, ensure_ascii=False, default=str)}]}
        except Exception as exc:
            return {"content": [{"type": "text", "text": "ошибка: %s" % exc}], "isError": True}
    raise ValueError("неизвестный метод: %s" % method)


def reply(payload):
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")
    sys.stdout.flush()


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue
        for one in (request if isinstance(request, list) else [request]):
            if "id" not in one:
                try:
                    dispatch(one)
                except Exception:
                    pass
                continue
            try:
                result = dispatch(one)
            except Exception as exc:
                reply({"jsonrpc": "2.0", "id": one["id"],
                       "error": {"code": -32603, "message": str(exc)}})
                continue
            if result is not None:
                reply({"jsonrpc": "2.0", "id": one["id"], "result": result})


if __name__ == "__main__":
    main()
