from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import urllib.parse as up
import os, secrets, http.cookies

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "portal" / "templates"

def render(name: str, **ctx) -> bytes:
    html = (TEMPLATES / name).read_text(encoding="utf-8")
    for k, v in ctx.items():
        html = html.replace(f"{{{{ {k} }}}}", str(v))
    return html.encode("utf-8")

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/static/"):
            path = ROOT / "portal" / self.path.strip("/")
            if path.exists():
                self.send_response(200)
                if path.suffix == ".css":
                    self.send_header("Content-Type", "text/css; charset=utf-8")
                self.end_headers()
                self.wfile.write(path.read_bytes()); return
            self.send_error(404); return

        if self.path in ("/", "/login"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(render("login.html", error=""))
            return

        if self.path == "/ok":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(render("ok.html")); return

        self.send_response(302); self.send_header("Location", "/"); self.end_headers()

    def do_POST(self):
        if self.path == "/login":
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("utf-8", "ignore")
            params = up.parse_qs(body)
            user = params.get("username", [""])[0].strip()
            pwd  = params.get("password", [""])[0]

            # Plantilla: validar no-vacío; luego reemplazar por core/auth.py (PBKDF2)
            if user and pwd:
                sid = secrets.token_urlsafe(32)
                jar = http.cookies.SimpleCookie()
                jar["sid"] = sid
                jar["sid"]["httponly"] = True
                jar["sid"]["path"] = "/"
                self.send_response(302)
                self.send_header("Location", "/ok")
                self.send_header("Set-Cookie", jar.output(header="", sep="").strip())
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(render("login.html", error="Credenciales inválidas"))
            return

        if self.path == "/logout":
            self.send_response(302); self.send_header("Location", "/"); self.end_headers(); return

        self.send_error(404)

    def log_message(self, *_):  # menos ruido en consola
        pass

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    with ThreadingHTTPServer(("0.0.0.0", port), Handler) as httpd:
        print(f"Portal escuchando en http://0.0.0.0:{port}")
        httpd.serve_forever()
