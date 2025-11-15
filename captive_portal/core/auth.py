from __future__ import annotations

import json
import hashlib
import secrets
from pathlib import Path
from typing import Dict

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
USERS_FILE = DATA_DIR / "users.json"

PBKDF2_ITERS = 200_000


def _pbkdf2(password: str, salt: bytes) -> str:
    """Devuelve el hash PBKDF2-HMAC-SHA256 en hex."""
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERS,
    )
    return dk.hex()


def load_users() -> Dict[str, Dict[str, str]]:
    """Carga los usuarios desde disco. Si no existe, devuelve dict vacío."""
    if not USERS_FILE.exists():
        return {}

    try:
        with USERS_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        return data
    except json.JSONDecodeError:
        return {}


def save_users(users: Dict[str, Dict[str, str]]) -> None:
    """Guarda el diccionario de usuarios a disco de forma segura."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = USERS_FILE.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)
    tmp.replace(USERS_FILE)


def create_user(username: str, password: str) -> None:
    """
    Crea un usuario nuevo con contraseña hasheada.
    Lanza ValueError si el usuario ya existe o username/password inválidos.
    """
    username = username.strip()
    if not username:
        raise ValueError("El nombre de usuario no puede estar vacío.")
    if ":" in username:
        raise ValueError("El nombre de usuario no puede contener ':'.")
    if not password:
        raise ValueError("La contraseña no puede estar vacía.")

    users = load_users()
    if username in users:
        raise ValueError(f"El usuario '{username}' ya existe.")

    salt = secrets.token_bytes(16)
    password_hash = _pbkdf2(password, salt)

    users[username] = {
        "salt": salt.hex(),
        "hash": password_hash,
    }
    save_users(users)


def verify_user(username: str, password: str) -> bool:
    """Comprueba si (username, password) es válido según el fichero de usuarios."""
    users = load_users()
    info = users.get(username.strip())
    if not info:
        return False

    try:
        salt = bytes.fromhex(info["salt"])
        stored_hash = info["hash"]
    except (KeyError, ValueError):
        return False

    calc_hash = _pbkdf2(password, salt)
    return secrets.compare_digest(calc_hash, stored_hash)


def list_users() -> Dict[str, Dict[str, str]]:
    """Devuelve el diccionario de usuarios (sin exponer las contraseñas en claro)."""
    return load_users()
