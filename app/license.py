"""
Licencias de Hylanlock — verificación local y sin conexión.

El producto es self-hosted y LAN-only: NO puede "llamar a casa". Por eso la licencia se entrega como
un texto firmado por nosotros (Ed25519) y se verifica AQUÍ con la clave pública embebida más abajo.
La clave privada (que firma) nunca sale de nuestro lado (ver tools/keygen.py y tools/license_gen.py).

Formato:  base64url(claims_json) + "." + base64url(firma_ed25519)
  - Se firma EXACTAMENTE el claims_json (los bytes que viajan en la 1ª parte), sin reserializar.
Claims: { id, customer, type: 'trial'|'commercial', issued: 'YYYY-MM-DD',
          expires: 'YYYY-MM-DD', max_users: int (0 = sin límite) }

Módulo PURO: no hace IO de estado ni toca la BD. `evaluate()` recibe el texto de la licencia y el
'high-water mark' de fecha, y devuelve el estado + el nuevo high-water mark para que el llamador lo
persista. Así es fácil de testear y el anti-rollback vive fuera.
"""

import os
import json
import base64
from datetime import date

import ed25519_pure as ed  # verificación Ed25519 en Python puro (sin dependencias)

# Clave PÚBLICA de firma de licencias (generada con tools/keygen.py el 2026-08-25).
# Es pública por diseño: puede ir en el código. Su pareja privada firma las licencias.
LICENSE_PUBLIC_KEY = bytes.fromhex(
    "2a9832c0f567424f0bf5209b9132db7c7b440d809dbfca29225c0b53cd800b8f"
)

LICENSE_FILENAME = "license.key"

# Estados posibles.
VALID = "valid"        # firma correcta y dentro de fechas
EXPIRED = "expired"    # firma correcta pero caducada
INVALID = "invalid"    # firma incorrecta o formato corrupto
MISSING = "missing"    # no hay licencia instalada


# ------------------------------------------------------------------ base64url
def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# ------------------------------------------------------------------ formato
def pack(claims_json: bytes, signature: bytes) -> str:
    """Compone una licencia a partir del claims_json (bytes) y su firma. Usado por el generador."""
    return _b64url_encode(claims_json) + "." + _b64url_encode(signature)


def _verify_signature(message: bytes, signature: bytes) -> bool:
    """True si 'signature' es una firma válida de 'message' bajo nuestra clave pública."""
    return ed.verify(signature, message, LICENSE_PUBLIC_KEY)


def parse(text):
    """Devuelve los claims (dict) si el texto es una licencia con FIRMA VÁLIDA; si no, None.
    No mira fechas: solo autenticidad e integridad."""
    try:
        parts = (text or "").strip().split(".")
        if len(parts) != 2:
            return None
        claims_json = _b64url_decode(parts[0])
        signature = _b64url_decode(parts[1])
        if len(signature) != 64:
            return None
        if not _verify_signature(claims_json, signature):
            return None
        claims = json.loads(claims_json.decode("utf-8"))
        return claims if isinstance(claims, dict) else None
    except Exception:
        return None


# ------------------------------------------------------------------ IO
def read_license_file(data_dir):
    """Lee el contenido de <data_dir>/license.key, o None si no existe/ilegible."""
    try:
        path = os.path.join(data_dir, LICENSE_FILENAME)
        with open(path, "r", encoding="ascii") as f:
            return f.read().strip()
    except Exception:
        return None


# ------------------------------------------------------------------ evaluación
def evaluate(text, seen_iso=None, today=None):
    """Evalúa una licencia y devuelve un dict con el estado.

    - text:      contenido de license.key (o None si no hay).
    - seen_iso:  'high-water mark' de fecha guardado (str 'YYYY-MM-DD') o None. Anti-rollback:
                 la fecha efectiva es max(hoy, seen), así atrasar el reloj no revive la licencia.
    - today:     datetime.date (por defecto hoy). Parametrizable para tests.

    Devuelve: {status, claims, customer, type, expires, days_left, reason, new_seen}
              'new_seen' es el high-water mark actualizado que el llamador debe persistir.
    """
    today = today or date.today()
    today_iso = today.isoformat()
    # high-water mark: nunca retrocede.
    seen = seen_iso if (seen_iso and seen_iso > today_iso) else today_iso
    base = {"status": MISSING, "claims": None, "customer": None, "type": None,
            "expires": None, "days_left": None, "reason": "", "new_seen": seen}

    if not text or not text.strip():
        base["reason"] = "No hay licencia instalada."
        return base

    claims = parse(text)
    if claims is None:
        base["status"] = INVALID
        base["reason"] = "La licencia no es válida (firma o formato incorrectos)."
        return base

    expires = claims.get("expires")
    try:
        exp_date = date.fromisoformat(expires)
    except Exception:
        base["status"] = INVALID
        base["reason"] = "La licencia tiene una fecha de caducidad inválida."
        return base

    eff_date = date.fromisoformat(seen)          # fecha efectiva = max(hoy, seen)
    days_left = (exp_date - eff_date).days
    status = VALID if eff_date <= exp_date else EXPIRED
    return {
        "status": status,
        "claims": claims,
        "customer": claims.get("customer"),
        "type": claims.get("type"),
        "expires": expires,
        "days_left": days_left,
        "reason": "" if status == VALID else "La licencia ha caducado.",
        "new_seen": seen,
    }
