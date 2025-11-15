from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import urllib.parse as up
import os, secrets, http.cookies

from core.auth import verify_user
from core.firewall import FirewallManager

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "portal" / "templates"

# Sesiones en memoria: sid -> { "user": str, "ip": str }
SESSIONS: dict[str, dict[str, str]] = {}

# Config del portal
PORT = int(os.getenv("PORT", "8080"))
# IP de la interfaz LAN de tu máquina (gateway de los clientes)
PORTAL_HOST = os.getenv("PORTAL_HOST", "10.42.0.1")

fw = FirewallManager(lan_iface="wlo1", wan_iface="usb0")


def portal_url(path: str) -> str:
    """
    Construye una URL absoluta hacia el portal, para que
    las redirecciones no dependan del Host original.
    """
    # Aseguramos que path empiece por "/"
    if not path.startswith("/"):
        path = "/" + path
    return f"http://{PORTAL_HOST}:{PORT}{path}"


def render(name: str, **ctx) -> bytes:
    html = (TEMPLATES / name).read_text(encoding="utf-8")
    for k, v in ctx.items():
        html = html.replace(f"{{{{ {k} }}}}", str(v))
    return html.encode("utf-8")


def get_sid_from_cookie(handler: BaseHTTPRequestHandler) -> str | None:
    cookie_header = handler.headers.get("Cookie")
    if not cookie_header:
        return None
    jar = http.cookies.SimpleCookie()
    jar.load(cookie_header)
    if "sid" in jar:
        return jar["sid"].value
    return None


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Archivos estáticos (CSS, JS, imágenes)
        if self.path.startswith("/static/"):
            path = ROOT / "portal" / self.path.strip("/")
            if path.exists():
                self.send_response(200)
                if path.suffix == ".css":
                    self.send_header("Content-Type", "text/css; charset=utf-8")
                self.end_headers()
                self.wfile.write(path.read_bytes())
                return
            self.send_error(404)
            return

        # Comprobamos sesión
        sid = get_sid_from_cookie(self)
        session = SESSIONS.get(sid) if sid else None

        # Página principal / login
        if self.path in ("/", "/login"):
            # Si ya está logueado, mandarlo directo a /ok
            if session:
                self.send_response(302)
                self.send_header("Location", portal_url("/ok"))
                self.end_headers()
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(render("login.html", error=""))
            return

        # Página "ok" (solo si hay sesión válida)
        if self.path == "/ok":
            if not session:
                # Sin sesión -> al login del portal
                self.send_response(302)
                self.send_header("Location", portal_url("/login"))
                self.end_headers()
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(render("ok.html"))
            return

        # Cualquier otra ruta -> redirigimos a la raíz del portal
        self.send_response(302)
        self.send_header("Location", portal_url("/"))
        self.end_headers()

    def do_POST(self):
        # Login
        if self.path == "/login":
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("utf-8", "ignore")
            params = up.parse_qs(body)
            user = params.get("username", [""])[0].strip()
            pwd = params.get("password", [""])[0]

            # Validamos usuario contra la BD
            if verify_user(user, pwd):
                client_ip = self.client_address[0]

                # Creamos sesión
                sid = secrets.token_urlsafe(32)
                SESSIONS[sid] = {"user": user, "ip": client_ip}

                # Autorizamos IP en el firewall (bypass portal / NAT)
                fw.allow_client(client_ip)

                # Seteamos cookie de sesión
                jar = http.cookies.SimpleCookie()
                jar["sid"] = sid
                jar["sid"]["httponly"] = True
                jar["sid"]["path"] = "/"

                self.send_response(302)
                # ¡OJO!: redirigimos a URL absoluta del portal
                self.send_header("Location", portal_url("/ok"))
                self.send_header("Set-Cookie", jar.output(header="", sep="").strip())
                self.end_headers()
            else:
                # Usuario o contraseña inválidos
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(
                    render("login.html", error="Usuario o contraseña incorrectos")
                )
            return

        # Logout
        if self.path == "/logout":
            sid = get_sid_from_cookie(self)
            if sid and sid in SESSIONS:
                info = SESSIONS.pop(sid)
                client_ip = info.get("ip")

                if client_ip:
                    fw.block_client(client_ip)

            # Expirar cookie
            jar = http.cookies.SimpleCookie()
            jar["sid"] = ""
            jar["sid"]["path"] = "/"
            jar["sid"]["max-age"] = 0

            self.send_response(302)
            # Redirigimos a la raíz del portal
            self.send_header("Location", portal_url("/"))
            self.send_header("Set-Cookie", jar.output(header="", sep="").strip())
            self.end_headers()
            return

        # Cualquier otro POST no está soportado
        self.send_error(404)

    def log_message(self, *_):
        # Silenciar logs por consola
        pass


if __name__ == "__main__":
    # Reglas base del firewall (incluyendo la redirección HTTP→portal)
    fw.setup_base_rules()

    with ThreadingHTTPServer(("0.0.0.0", PORT), Handler) as httpd:
        print(f"Portal escuchando en http://0.0.0.0:{PORT}")
        httpd.serve_forever()
