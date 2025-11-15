from __future__ import annotations
import json
import time
import secrets
from pathlib import Path
from typing import Dict, Any

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
SESSIONS_FILE = DATA_DIR / "sessions.json"

# TTL de sesión en segundos (ej. 1 hora)
SESSION_TTL = 3600


def _load_sessions() -> Dict[str, Dict[str, Any]]:
    if not SESSIONS_FILE.exists():
        return {}
    try:
        with SESSIONS_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        return data
    except json.JSONDecodeError:
        return {}


def _save_sessions(sessions: Dict[str, Dict[str, Any]]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = SESSIONS_FILE.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(sessions, f, indent=2, ensure_ascii=False)
    tmp.replace(SESSIONS_FILE)


def _cleanup_expired(sessions: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    now = time.time()
    changed = False
    for sid in list(sessions.keys()):
        sess = sessions[sid]
        last_seen = sess.get("last_seen", sess.get("created_at", now))
        if now - last_seen > SESSION_TTL:
            del sessions[sid]
            changed = True
    if changed:
        _save_sessions(sessions)
    return sessions


def create(user: str, ip: str, mac: str | None) -> str:
    """
    Crea una nueva sesión persistente y devuelve el sid.
    Guarda user, ip, mac, created_at, last_seen.
    """
    sessions = _cleanup_expired(_load_sessions())

    sid = secrets.token_urlsafe(32)
    now = time.time()
    sessions[sid] = {
        "user": user,
        "ip": ip,
        "mac": mac or "",
        "created_at": now,
        "last_seen": now,
    }
    _save_sessions(sessions)
    return sid


def destroy(sid: str) -> None:
    sessions = _cleanup_expired(_load_sessions())
    if sid in sessions:
        del sessions[sid]
        _save_sessions(sessions)


def get(sid: str) -> Dict[str, Any] | None:
    """
    Devuelve la sesión si existe y no está expirada.
    Actualiza last_seen.
    """
    sessions = _cleanup_expired(_load_sessions())
    sess = sessions.get(sid)
    if not sess:
        return None

    now = time.time()
    last_seen = sess.get("last_seen", sess.get("created_at", now))
    if now - last_seen > SESSION_TTL:
        # Expirada justo ahora
        del sessions[sid]
        _save_sessions(sessions)
        return None

    sess["last_seen"] = now
    sessions[sid] = sess
    _save_sessions(sessions)
    return sess


def list_all() -> Dict[str, Dict[str, Any]]:
    """
    Devuelve todas las sesiones activas (TTL no expirado).
    """
    sessions = _cleanup_expired(_load_sessions())
    return sessions
