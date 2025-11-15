from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import urllib.parse as up
import os, secrets, http.cookies

from core.auth import verify_user
from core.firewall import FirewallManager
from core.arp import lookup_mac         
from core import sessions as sess_store 
from core.auth import create_user, list_users


ADMIN_IPS = {"127.0.0.1", "10.0.0.1"}  # cambia 10.0.0.1 por la IP de tu router


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "portal" / "templates"

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

def get_valid_session(handler: BaseHTTPRequestHandler):
    """
    Devuelve la sesión válida para esta petición o None.
    Aplica:
      - TTL (en sess_store.get)
      - Binding IP/MAC (anti suplantación)
    """
    sid = get_sid_from_cookie(handler)
    if not sid:
        return None

    session = sess_store.get(sid)
    if not session:
        return None

    client_ip = handler.client_address[0]
    client_mac = lookup_mac(client_ip) or ""

    # Comprobamos IP
    if session.get("ip") != client_ip:
        # IP distinta -> alguien está usando una cookie desde otra IP
        # o el cliente ha cambiado forzadamente su IP.
        # Lo tratamos como suplantación: eliminar sesión y bloquear IP actual.
        fw.block_client(client_ip)
        sess_store.destroy(sid)
        return None

    # Comprobamos MAC (si tenemos almacenada)
    stored_mac = (session.get("mac") or "").lower()
    if stored_mac and client_mac and stored_mac != client_mac.lower():
        # Misma IP pero MAC distinta -> suplantación ARP
        fw.block_client(client_ip)
        sess_store.destroy(sid)
        return None

    return session


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

        session = get_valid_session(self)

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
        
        if self.path == "/terms":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(render("terms.html"))
            return
        
        if path == "/admin_users":
            if not self._is_admin_request():
                self.send_error(403, "Forbidden")
                return
            self._render_admin_users()
            return


        # Cualquier otra ruta -> redirigimos a la raíz del portal
        self.send_response(302)
        self.send_header("Location", portal_url("/"))
        self.end_headers()

    def do_POST(self):
        parsed = up.urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length).decode("utf-8")
        data = dict(up.parse_qsl(body))

        # Login
        if self.path == "/login":
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("utf-8", "ignore")
            params = up.parse_qs(body)
            user = params.get("username", [""])[0].strip()
            pwd = params.get("password", [""])[0]

            if verify_user(user, pwd):
                client_ip = self.client_address[0]
                client_mac = lookup_mac(client_ip) or ""

                sid = sess_store.create(user, client_ip, client_mac)
                fw.allow_client(client_ip)

                jar = http.cookies.SimpleCookie()
                jar["sid"] = sid
                jar["sid"]["httponly"] = True
                jar["sid"]["path"] = "/"

                self.send_response(302)
                self.send_header("Location", portal_url("/ok"))
                self.send_header("Set-Cookie", jar.output(header="", sep="").strip())
                self.end_headers()
            else:
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
            if sid:
                session = sess_store.get(sid)
                if session:
                    client_ip = session.get("ip")
                    if client_ip:
                        fw.block_client(client_ip)
                sess_store.destroy(sid)

            # Expirar cookie
            jar = http.cookies.SimpleCookie()
            jar["sid"] = ""
            jar["sid"]["path"] = "/"
            jar["sid"]["max-age"] = 0

            self.send_response(302)
            self.send_header("Location", portal_url("/"))
            self.send_header("Set-Cookie", jar.output(header="", sep="").strip())
            self.end_headers()
            return
        
        if self.path == "/admin_users":
            if not self._is_admin_request():
                self.send_error(403, "Forbidden")
                return

            username = data.get("username", "").strip()
            pwd1 = data.get("password", "")
            pwd2 = data.get("password2", "")

            if not username:
                self._render_admin_users(error="El nombre de usuario no puede estar vacío.")
                return

            if pwd1 != pwd2:
                self._render_admin_users(error="Las contraseñas no coinciden.")
                return

            try:
                create_user(username, pwd1)
            except ValueError as e:
                # mismo comportamiento que tu script de consola
                self._render_admin_users(error=f"Error al crear usuario: {e}")
                return

            # Usuario creado OK
            self._render_admin_users(success=f"Usuario '{username}' creado correctamente.")
            return


        # Cualquier otro POST no está soportado
        self.send_error(404)

    def log_message(self, *_):
        # Silenciar logs por consola
        pass

        
    #Admin
    def _is_admin_request(self) -> bool:
        client_ip, _ = self.client_address
        return client_ip in ADMIN_IPS
    
    def _render_admin_users(
        self,
        error: str | None = None,
        success: str | None = None,) -> None:
        # construir bloque de errores / éxito
        if error:
            error_block = f'<div class="alert-error">{error}</div>'
        else:
            error_block = ""

        if success:
            success_block = f'<div class="alert-success">{success}</div>'
        else:
            success_block = ""

        # Construir lista de usuarios
        users_html_items = []
        for u in list_users().keys():
            users_html_items.append(f"<li>{u}</li>")
        users_list = "\n".join(users_html_items) or "<li><em>No hay usuarios aún</em></li>"

        tpl_path = TEMPLATES / "admin_users.html"
        html = tpl_path.read_text(encoding="utf-8").format(
            error_block=error_block,
            success_block=success_block,
            users_list=users_list,
        )

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))


if __name__ == "__main__":
    # Reglas base del firewall (incluyendo la redirección HTTP→portal)
    fw.setup_base_rules()

    with ThreadingHTTPServer(("0.0.0.0", PORT), Handler) as httpd:
        print(f"Portal escuchando en http://0.0.0.0:{PORT}")
        httpd.serve_forever()
