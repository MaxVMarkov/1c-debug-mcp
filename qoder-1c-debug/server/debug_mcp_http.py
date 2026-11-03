"""HTTP-транспорт MCP для плагина: POST http://127.0.0.1:<порт>/mcp.

Re-shoot / запуск: python qoder-1c-debug/server/debug_mcp_http.py --port 8123

Тип `http` — единственная форма декларации MCP в плагине Qoder, которая у нас уже
работает (`1c-syntax-helper` на :8000, `delphi-mcp` на :3000); stdio в этой машине ещё
не проверен, поэтому он оставлен только для отладки инструментов через
`debug_mcp.py`.

Ответ всегда application/json: потоковый SSE здесь не нужен, потому что событийную
модель обеспечивает сам сеанс отладки (фоновый цикл `pingDebugUIParams` в mcp_core).
"""
import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import mcp_core as core

if hasattr(sys.stdout, "reconfigure"):
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


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
            request = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception as exc:
            self._send(400, {"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32700, "message": str(exc)}})
            return
        for one in (request if isinstance(request, list) else [request]):
            if "id" not in one:
                try:
                    dispatch(one)
                except Exception:
                    pass
                self._send(202, b"", "application/json")
                continue
            try:
                result = dispatch(one)
            except Exception as exc:
                self._send(200, {"jsonrpc": "2.0", "id": one["id"],
                                 "error": {"code": -32603, "message": str(exc)}})
                continue
            self._send(200, {"jsonrpc": "2.0", "id": one["id"],
                             "result": result if result is not None else {}})

    def do_GET(self):
        # health-check для scripts/status.ps1: поднят ли сервер
        self._send(200, {"server": core.SERVER_INFO, "tools": [t["name"] for t in core.TOOLS]})

    def _send(self, status, payload, content_type="application/json"):
        body = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8123)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print("1c-debug MCP на http://%s:%d/mcp (инструментов: %d)"
          % (args.host, args.port, len(core.TOOLS)), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
