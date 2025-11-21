import socket
import threading


class BaseHTTPRequestHandler:
    """
    Handler HTTP mínimo compatible con lo que usa tu Handler:
    - self.path
    - self.headers (dict con .get)
    - self.rfile / self.wfile
    - self.client_address
    - send_response / send_header / end_headers / send_error / log_message
    """

    # Usamos HTTP/1.0 para que el cierre de conexión marque el fin del cuerpo
    protocol_version = "HTTP/1.0"

    _RESPONSES = {
        200: "OK",
        302: "Found",
        400: "Bad Request",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        500: "Internal Server Error",
    }

    def __init__(self, conn, client_address, server):
        self.connection = conn
        self.client_address = client_address
        self.server = server

        # Ficheros de lectura/escritura sobre el socket
        self.rfile = conn.makefile("rb")
        self.wfile = conn.makefile("wb")

        self.headers: dict[str, str] = {}
        self.command: str | None = None
        self.path: str | None = None
        self.request_version: str | None = None

        try:
            self.handle()
        finally:
            # Cerramos todo al terminar la petición
            try:
                self.wfile.flush()
            except Exception:
                pass
            for f in (self.wfile, self.rfile, self.connection):
                try:
                    f.close()
                except Exception:
                    pass

    # --------- Parseo de la petición ---------
    def handle(self):
        # Línea de petición: "GET /ruta HTTP/1.1"
        request_line = self.rfile.readline(65537)
        if not request_line:
            return

        try:
            request_line = request_line.decode("iso-8859-1").rstrip("\r\n")
            parts = request_line.split()
            if len(parts) != 3:
                self.send_error(400, "Bad Request")
                return
            self.command, self.path, self.request_version = parts
        except Exception:
            self.send_error(400, "Bad Request")
            return

        # Cabeceras HTTP terminadas en una línea en blanco
        self.headers = {}
        while True:
            line = self.rfile.readline(65537)
            if not line:
                break
            if line in (b"\r\n", b"\n"):
                break  # fin de cabeceras
            try:
                line = line.decode("iso-8859-1")
            except UnicodeDecodeError:
                continue
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            self.headers[name.strip()] = value.strip()

        # Buscar método do_GET / do_POST / ...
        method = getattr(self, f"do_{self.command}", None)
        if method is None:
            self.send_error(405, "Method Not Allowed")
            return

        method()

    # --------- API de respuesta ---------
    def send_response(self, code, message=None):
        if message is None:
            message = self._RESPONSES.get(code, "OK")
        status_line = f"{self.protocol_version} {code} {message}\r\n"
        self.wfile.write(status_line.encode("iso-8859-1"))

    def send_header(self, name, value):
        header_line = f"{name}: {value}\r\n"
        self.wfile.write(header_line.encode("iso-8859-1"))

    def end_headers(self):
        # Línea en blanco que separa cabeceras y cuerpo
        self.wfile.write(b"\r\n")

    def send_error(self, code, message=None):
        if message is None:
            message = self._RESPONSES.get(code, "Error")

        body = (
            f"<html><head><title>Error {code}</title></head>"
            f"<body><h1>{code} {message}</h1></body></html>"
        )
        body_bytes = body.encode("utf-8")

        self.send_response(code, message)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    def log_message(self, fmt, *args):
        addr = self.client_address[0] if self.client_address else "?"
        msg = fmt % args if args else fmt
        print(f"[{addr}] {msg}")


class ThreadingHTTPServer:
    """
    Servidor HTTP muy simple con un hilo por conexión.
    Imitamos la interfaz de http.server.ThreadingHTTPServer:
      - __init__(address, handler_class)
      - serve_forever()
      - server_close()
      - contexto "with ... as httpd:"
    """

    def __init__(self, server_address, handler_class):
        self.server_address = server_address
        self.RequestHandlerClass = handler_class
        self._shutdown = False

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(server_address)
        self.socket.listen(5)

    def _handle_client(self, conn, addr):
        try:
            self.RequestHandlerClass(conn, addr, self)
        except Exception as e:
            print(f"Error atendiendo a {addr}: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def serve_forever(self):
        try:
            while not self._shutdown:
                try:
                    conn, addr = self.socket.accept()
                except OSError:
                    break  # socket cerrado en shutdown
                t = threading.Thread(
                    target=self._handle_client, args=(conn, addr), daemon=True
                )
                t.start()
        finally:
            self.server_close()

    def server_close(self):
        try:
            self.socket.close()
        except Exception:
            pass

    def shutdown(self):
        self._shutdown = True
        try:
            self.socket.close()
        except Exception:
            pass

    # Soporte para "with ThreadingHTTPServer(...) as httpd:"
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.shutdown()
