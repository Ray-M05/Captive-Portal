# Flujo de autenticación del portal cautivo

## Resumen general

El portal cautivo implementa autenticación basada en sesión usando una
cookie `sid`. El comportamiento global es:

-   Cada vez que un dispositivo realiza un login correcto:

    -   Se crea una nueva sesión en el servidor: `sid` $\rightarrow$ {
        `user`, `ip`, `mac` }.

    -   Se envía una cookie `sid` al navegador.

    -   Se abre el firewall para la dirección IP de ese cliente.

-   Se permiten múltiples dispositivos usando las mismas credenciales
    (multi--login por usuario).

-   Existe un mecanismo de **anti-suplantación de sesión**: si se
    reutiliza un `sid` desde otra IP y/o otra MAC distinta, se bloquea
    ese acceso.

# Flujo de inicio de sesión (`POST /login`)

Cuando un cliente envía el formulario de login (usuario y contraseña),
el servidor sigue el siguiente flujo lógico:

1.  Recibir la petición `POST /login` con los parámetros `username` y
    `password`.

2.  Verificar credenciales:

    -   Si `verify_user(user, pwd)` es **falso**:

        -   Responder con `200 OK`.

        -   Renderizar `login.html` con un mensaje de error
            (p. ej. "Usuario o contraseña incorrectos").

        -   No se crea sesión ni se modifica el firewall.

    -   Si `verify_user(user, pwd)` es **verdadero**:

        -   Obtener la IP real del cliente:
            `client_ip = self.client_address[0]`.

        -   Resolver la MAC asociada (si el sistema lo permite):
            `client_mac = lookup_mac(client_ip) or ""`.

        -   Crear siempre una nueva sesión independiente:

            -   `sid = sess_store.create(user, client_ip, client_mac)`.

        -   Abrir el paso en el firewall para esa IP:
            `fw.allow_client(client_ip)`.

        -   Enviar cookie de sesión:

            ``` {.python language="Python"}
            Set-Cookie: sid=<sid>; HttpOnly; Path=/
            ```

        -   Responder con redirección:

                HTTP/1.0 302 Found
                Location: /ok

Observaciones importantes:

-   No se comprueba si ese usuario ya tiene otras sesiones activas. Cada
    dispositivo obtiene su propio `sid` y su propia entrada
    `{user, ip, mac}`.

-   El control de seguridad se basa en la pareja (`sid`, IP, MAC), no en
    "un usuario, un dispositivo".

# Comprobación de autenticación en cada petición

Para decidir si un cliente está autenticado, el servidor sigue la
lógica:

``` {.python language="Python"}
sid = get_sid_from_cookie(handler)     # Lee Cookie: sid=...
session = get_valid_session(handler)   # Valida sid + IP + MAC
```

La función conceptual `get_valid_session(handler)` realiza:

1.  Lectura de la cookie:

    -   Si no hay cookie `sid`: `return None` (usuario no autenticado).

    -   Si el `sid` no existe en el almacenamiento de sesiones:
        `return None`.

2.  Si la sesión existe:

    -   Recuperar la sesión: `session = { user, ip, mac, …}`.

    -   Obtener la IP y MAC actuales del cliente:

        ``` {.python language="Python"}
        client_ip  = handler.client_address[0]
        client_mac = lookup_mac(client_ip) or ""
        stored_ip  = session["ip"]
        stored_mac = (session.get("mac") or "").lower()
        ```

    -   Aplicar las reglas de anti-suplantación

    -   Si las comprobaciones pasan, devolver `session`; en otro caso,
        `None`.

## Redirecciones según el estado de sesión

### Ruta `/` (página principal / login)

-   Si `get_valid_session` devuelve una sesión válida:

    -   Responder con `302 Location: /ok`.

-   Si no hay sesión válida:

    -   Responder con `200 OK` y renderizar `login.html`.

### Ruta `/ok` (página de éxito)

-   Si no hay sesión válida:

    -   Responder con `302 Location: /login`.

-   Si hay sesión válida:

    -   Responder con `200 OK` y mostrar la página de "acceso concedido"
        (por ejemplo, indicando el usuario autenticado).

### Ruta `/logout`

1.  Leer `sid` desde la cookie.

2.  Buscar la sesión correspondiente en el almacenamiento.

3.  Si existe:

    -   Obtener la IP asociada a esa sesión.

    -   Llamar a `fw.block_client(ip)` para cerrar el tráfico de esa IP
        en el firewall.

    -   Eliminar la sesión: `sess_store.destroy(sid)`.

4.  Enviar una cookie `sid` vacía con `max-age=0` para borrarla en el
    navegador.

5.  Responder con `302 Location: /` (volver a la pantalla de login).

# Casos de anti-suplantación {#sec:antisup}

Cada sesión almacena la siguiente información mínima:

  `sid`    Identificador de sesión
  `user`   Nombre de usuario autenticado
  `ip`     IP desde la que se creó la sesión
  `mac`    MAC asociada a esa IP en el momento del login

En cada petición autenticada, se comprueban distintos casos:

## Caso 1: IP distinta con el mismo `sid`

**Escenario:**

-   Un atacante roba la cookie `sid` de otro usuario.

-   Intenta usar ese mismo `sid` desde otra IP (otro dispositivo).

**Detección:**

``` {.python language="Python"}
if stored_ip != client_ip:
    # suplantación de sesión por IP
    fw.block_client(client_ip)
    sess_store.destroy(sid)
    return None
```

**Efecto:**

-   Se bloquea la IP que intentó usar el `sid` robado.

-   Se destruye la sesión.

-   El handler recibe `session = None` y tratará al cliente como no
    autenticado (redirigiéndolo a `/login`).

## Caso 2: Misma IP pero MAC distinta

**Escenario típico:**

-   Alguien en la LAN se configura con la misma IP que la víctima (ARP
    spoofing).

-   Intenta usar el mismo `sid`.

**Detección:**

``` {.python language="Python"}
if stored_mac and client_mac and stored_mac != client_mac.lower():
    # misma IP, otra MAC -> suplantación ARP
    fw.block_client(client_ip)
    sess_store.destroy(sid)
    return None
```

**Efecto:**

-   Se bloquea la IP en el firewall.

-   Se invalida la sesión.

-   El cliente será redirigido a `/login` en la siguiente petición
    protegida.

## Caso 3: Misma IP, misma MAC, mismo `sid`

-   Es el caso normal: el mismo dispositivo legítimo usando su propia
    sesión.

-   No se dispara ninguna lógica de anti-suplantación.

-   `get_valid_session` devuelve la sesión y el usuario se considera
    autenticado.

## Caso 4: Misma IP, MAC distinta, pero *sin* `sid`

-   La petición no trae cookie `sid`.

-   El servidor no puede asociar esa petición con ninguna sesión
    existente.

-   `get_valid_session` devuelve directamente `None`.

-   La petición se trata como "no autenticada":

    -   En `/` se muestra `login.html`.

    -   En `/ok` se redirige a `/login`.

-   En este punto no es posible aplicar anti-suplantación basada en
    sesiones, porque no hay `sid` contra el que comparar.
