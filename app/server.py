"""Small, dependency-free API for a disposable security demonstration."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            code, data = 200, {"status": "ok"}
        elif self.path == "/":
            code, data = 200, {"project": "trusted-container-pipeline"}
        else:
            code, data = 404, {"error": "not found"}
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
