# Captive Portal

## Estructura
- portal/ → servidor HTTP, templates y estáticos
- core/   → lógica (auth, sesiones, firewall, ARP, config)
- data/   → ficheros de usuarios/sesiones
- scripts/→ utilidades de red (bootstrap/teardown)

## Ejecutar demo
```bash
sudo python3 portal/server.py
# Abre: http://localhost:8080
```
