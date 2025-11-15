from getpass import getpass
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.auth import create_user, list_users 


def main() -> None:
    print("=== Alta de usuario para el portal cautivo ===")
    username = input("Nombre de usuario: ").strip()
    if not username:
        print("✗ El nombre de usuario no puede estar vacío.")
        return

    pwd1 = getpass("Contraseña: ")
    pwd2 = getpass("Repite la contraseña: ")

    if pwd1 != pwd2:
        print("✗ Las contraseñas no coinciden.")
        return

    try:
        create_user(username, pwd1)
    except ValueError as e:
        print(f"✗ Error: {e}")
        return

    print(f"✓ Usuario '{username}' creado correctamente.\n")

    print("Usuarios registrados actualmente:")
    for u in list_users().keys():
        print(f" - {u}")


if __name__ == "__main__":
    main()
