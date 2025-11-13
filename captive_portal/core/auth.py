# TODO: Implementar PBKDF2 + users.json (hashlib.pbkdf2_hmac + hmac.compare_digest)
def verify(username: str, password: str) -> bool:
    return bool(username and password)
