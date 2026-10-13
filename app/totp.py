"""Códigos de un solo uso por tiempo (TOTP, RFC 6238) — solo librería estándar.

Compatible con Google Authenticator, Microsoft Authenticator, Aegis, 2FAS, Bitwarden… El secreto
se comparte UNA vez (QR al activar) y desde entonces el móvil y el servidor calculan el mismo código
de 6 cifras cada 30 s sin hablar entre ellos: nada sale de la red.
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

STEP = 30          # segundos por código
DIGITS = 6
WINDOW = 1         # se acepta el código anterior y el siguiente (relojes algo desfasados)


def new_secret():
    """Secreto aleatorio de 160 bits en base32 sin relleno (lo que esperan las apps)."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def valid_secret(secret):
    try:
        return len(_key(secret)) >= 10
    except (ValueError, TypeError):
        return False


def _key(secret):
    s = (secret or "").strip().replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def code_at(secret, counter, digits=DIGITS):
    mac = hmac.new(_key(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    n = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 10 ** digits
    return str(n).zfill(digits)


def verify(secret, code, last_counter=0, now=None):
    """Devuelve el contador del código si es válido Y posterior al último usado (anti-reutilización:
    un código ya usado, o uno más antiguo, no vuelve a valer). None si no vale."""
    code = "".join(ch for ch in str(code or "") if ch.isdigit())
    if len(code) != DIGITS:
        return None
    actual = int((time.time() if now is None else now) // STEP)
    for counter in range(actual - WINDOW, actual + WINDOW + 1):
        if counter > last_counter and hmac.compare_digest(code_at(secret, counter), code):
            return counter
    return None


def uri(secret, account, issuer="Hylanlock"):
    """otpauth:// para el QR. La app muestra 'issuer (account)'."""
    label = quote(f"{issuer}:{account}")
    return (f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={DIGITS}&period={STEP}")
