# -*- coding: utf-8 -*-
"""
Hylanlock - Transferencia de archivos self-hosted para empresas (producto).

Servidor de transferencia de archivos para uso interno de una empresa: multiusuario con
departamentos, subcarpetas privadas y permisos por acción; aislado en la red local; subida
por trozos con reanudación; integridad SHA-256; auditoría; API de solo lectura para
integraciones; y agente de sincronización al PC del empleado.

TODO se configura por variables de entorno (prefijo HYLANLOCK_): no hay nada que editar en el
código. Sin dependencias: solo la biblioteca estándar de Python (más qr.py, incluido).

Uso:
    python hylanlock.py
"""

import os
import io
import sys
import csv
import time
import json
import hmac
import base64
import socket
import hashlib
import ipaddress
import secrets
import threading
import webbrowser
import urllib.request
from urllib.parse import unquote, quote, urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import html

import qr  # generador de QR local (qr.py)
import db  # base de datos de auditoría (db.py)
import license  # verificación de licencia/trial offline (license.py)
import totp  # códigos de un solo uso por tiempo para el 2FA (totp.py)
import ldap_auth  # login opcional contra Active Directory / LDAP (ldap_auth.py)

# ============================================================ CONFIGURACION
# Producto self-hosted: TODO configurable por variables de entorno (prefijo HYLANLOCK_).
# Pensado para Docker (variables) y para arranque manual. Nada personal en el código.
def _env(name, default=""):
    return os.environ.get("HYLANLOCK_" + name, default)

PORT = int(_env("PORT", "8000"))
# Dirección de escucha. Por defecto 0.0.0.0 (todas las interfaces). Detrás de un reverse proxy
# TLS (Caddy), ponlo a 127.0.0.1 para que SOLO el proxy pueda hablarle (y nadie salte el HTTPS).
BIND = _env("BIND", "0.0.0.0")
# Pista explícita de que se sirve por HTTPS (perfil Caddy): activa la cookie 'Secure' y HSTS. Además
# se detecta por 'X-Forwarded-Proto: https' del proxy de confianza. Por defecto 0 (LAN por HTTP).
BEHIND_TLS = _env("BEHIND_TLS", "0").strip().lower() in ("1", "true", "yes")
# HTTPS PROPIO (sin proxy): si se dan un certificado y su clave (PEM), el servidor sirve cifrado
# directamente. Es la vía simple para quitar el "No es seguro" sin montar Caddy. Si falta cualquiera
# de los dos, se sigue sirviendo por HTTP (como hasta ahora). Caddy sigue disponible para alta carga.
TLS_CERT = _env("TLS_CERT", "").strip()       # ruta al certificado PEM (p. ej. /certs/hylanlock.crt)
TLS_KEY = _env("TLS_KEY", "").strip()         # ruta a la clave privada PEM (p. ej. /certs/hylanlock.key)
TLS_ON = bool(TLS_CERT and TLS_KEY)           # True = HTTPS propio activo
# Enlace de feedback que el producto MUESTRA (no envía nada él mismo: el admin hace clic y rellena en
# su navegador, así no se rompe la promesa de "nada sale de tu red"). Vacío = no mostrar el aviso.
FEEDBACK_URL = _env("FEEDBACK_URL", "https://hylanlock.vercel.app/feedback")
ORG_NAME = _env("ORG_NAME", "Hylanlock")     # nombre de la organización (etiqueta en la UI)
# ── Marca blanca (branding por instalación) ─────────────────────────────────────────
BRAND_NAME = _env("BRAND_NAME", "Hylanlock")  # nombre visible del producto en la interfaz
BRAND_LOGO = _env("BRAND_LOGO", "")          # logo del sidebar: vacío = candado SVG por defecto (serio)
# Logo por defecto: un candado SVG monocromo (hereda el color del recuadro). Sin emojis.
BRAND_LOGO_SVG = ('<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" '
                  'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
                  '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>')


def _nav_svg(inner):
    """Icono SVG monocromo de 18px que hereda el color del texto (para el menú lateral)."""
    return ('<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" '
            'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' + inner + '</svg>')


_NAV_ICONS = {
    "home":     _nav_svg('<path d="M3 11l9-8 9 8"/><path d="M5 10v10h5v-6h4v6h5V10"/>'),
    "building": _nav_svg('<rect x="4" y="3" width="16" height="18" rx="1"/>'
                         '<path d="M9 7h2M13 7h2M9 11h2M13 11h2M9 15h2M13 15h2"/>'),
    "user":     _nav_svg('<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>'),
    "shield":   _nav_svg('<path d="M12 3l7 3v5c0 4.5-3 7.6-7 9-4-1.4-7-4.5-7-9V6z"/>'),
    "trash":    _nav_svg('<path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M6 6l1 14h10l1-14"/>'),
    "eye":      _nav_svg('<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>'),
    "list":     _nav_svg('<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>'),
    "cog":      _nav_svg('<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1'
                         'a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-2.7 1.1V21a2 2 0 0 1-4 0v-.2a1.6 1.6 0'
                         ' 0 0-2.7-1.1l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1A1.6 1.6 0 0 0 4 15H3a2 2 0 0 1 0-4h.2'
                         'A1.6 1.6 0 0 0 4.6 8.5l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1A1.6 1.6 0 0 0 10 4.6V3a2 2 0'
                         ' 0 1 4 0v.2a1.6 1.6 0 0 0 2.7 1.1l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0 1.1'
                         ' 2.7H21a2 2 0 0 1 0 4h-.2a1.6 1.6 0 0 0-1.4.9z"/>'),
}
ACCENT = _env("ACCENT", "").strip()            # color de acento (#rrggbb); vacío = el de fábrica
APP_VERSION = _env("VERSION", "1.0")           # versión del producto (visible en Ajustes → Acerca de)

# Provisioning del admin (despliegue automático / Docker). Si NO hay usuarios y se define
# ADMIN_PASSWORD, se crea el admin en el 1er arranque. (Asistente web de alta: pendiente.)
ADMIN_USER = _env("ADMIN_USER", "admin")
PASSWORD = _env("ADMIN_PASSWORD", "")        # vacío = no sembrar admin automáticamente

# Carpeta de datos. En Docker: un volumen. Por defecto: ./data junto a la app.
DATA_DIR = _env("DATA_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))

# Subredes consideradas "red local" (LAN) para el aislamiento por departamento.
# Por defecto: TODO rango privado RFC1918. El admin puede acotarlo (ej. "192.168.10.0/24").
LAN_CIDRS = [c.strip() for c in
             _env("LAN_CIDR", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16").split(",") if c.strip()]
_LAN_NETS = []
for _c in LAN_CIDRS:
    try:
        _LAN_NETS.append(ipaddress.ip_network(_c, strict=False))
    except ValueError:
        pass


def _ip_in(ip, nets):
    """True si la IP (str) pertenece a alguna de las subredes dadas."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in nets)


def ip_es_lan(ip):
    """True si la IP pertenece a alguna subred LAN configurada (proxy/127.0.0.1 -> False)."""
    return _ip_in(ip, _LAN_NETS)


# Proxies de confianza (para TLS / proxy inverso, p. ej. Caddy). Por defecto VACÍO -> se usa SIEMPRE
# la IP del socket (comportamiento actual: no se confía en ninguna cabecera). Solo si la conexión
# llega DESDE una de estas subredes se lee X-Forwarded-For para recuperar la IP real del cliente.
TRUSTED_PROXY_CIDRS = [c.strip() for c in _env("TRUSTED_PROXIES", "").split(",") if c.strip()]
_TRUSTED_PROXY_NETS = []
for _c in TRUSTED_PROXY_CIDRS:
    try:
        _TRUSTED_PROXY_NETS.append(ipaddress.ip_network(_c, strict=False))
    except ValueError:
        pass


def real_client_ip(peer_ip, xff_header):
    """IP real del cliente, resistente a spoofing.

    - Sin proxies de confianza configurados, o si el que conecta no es uno -> IP del socket (peer).
    - Si el peer ES un proxy de confianza y hay X-Forwarded-For -> la IP más a la derecha del XFF
      que NO sea a su vez un proxy de confianza (el cliente real detrás del/los proxy/proxies).

    Como solo se lee el XFF cuando la conexión viene de un proxy de confianza, un cliente cualquiera
    no puede falsear su IP (ni fingir estar en la LAN) mandando la cabecera él mismo.
    """
    if not _TRUSTED_PROXY_NETS or not _ip_in(peer_ip, _TRUSTED_PROXY_NETS):
        return peer_ip
    if not xff_header:
        return peer_ip
    for cand in reversed([p.strip() for p in xff_header.split(",") if p.strip()]):
        if not _ip_in(cand, _TRUSTED_PROXY_NETS):
            return cand
    return peer_ip


CHUNK_READ = 1024 * 1024          # 1 MB por lectura
PART_MAX_AGE = 7 * 24 * 3600      # limpiar trozos abandonados de +7 dias
# Tope del total de trozos incompletos (H1): la purga por edad acota el desgaste EN EL TIEMPO,
# pero no un pico rápido. Sin esto, mandar trozos que nunca se completan podría llenar el disco en
# minutos. Al superarlo, /upload/chunk responde 507 y NO escribe. 0 = sin límite. Por defecto 2 GB.
try:
    INCOMPLETE_MAX_BYTES = max(0, int(_env("INCOMPLETE_MAX_MB", "2048") or "2048")) * 1024 * 1024
except ValueError:
    INCOMPLETE_MAX_BYTES = 2048 * 1024 * 1024


# Anti-fuerza-bruta: tras LOGIN_MAX_FAILS fallos de una IP en LOGIN_WINDOW s -> bloqueo (429).
LOGIN_WINDOW = 900        # 15 min
LOGIN_MAX_FAILS = 8

# Duración de sesión si se marca "Recordar". Si no, cookie de sesión (equipos compartidos).
SESSION_DAYS = int(_env("SESSION_DAYS", "7"))

# Step-up / sudo: las acciones privilegiadas (administración) exigen re-autenticación reciente.
# La "elevación" dura estos minutos (el login cuenta como elevación inicial).
STEPUP_MINUTES = int(_env("STEPUP_MINUTES", "15"))
# ── Política de contraseñas ──────────────────────────────────────────────────────────
# Parte A (la decide CADA empresa por .env): caducidad del enlace, longitud mínima, si el admin
# puede fijar contraseñas directas y qué método se sugiere al crear un usuario.
# Parte B (FIJA, innegociable): las contraseñas se guardan hasheadas; NADIE puede verlas.
INVITE_HOURS = int(_env("INVITE_HOURS", "48"))            # caducidad de los enlaces de invitación
MIN_PASSWORD = max(6, int(_env("MIN_PASSWORD", "8")))     # longitud mínima (suelo de seguridad: 6)
ALLOW_DIRECT_PW = _env("ALLOW_DIRECT_PW", "1") == "1"     # 0 = SOLO invitación (el admin nunca fija claves)
PW_METHOD = _env("PW_METHOD", "invite").lower()           # método sugerido al crear usuario
if PW_METHOD not in ("invite", "direct") or not ALLOW_DIRECT_PW:
    PW_METHOD = "invite"                                  # sin fijado directo, siempre invitación

# ── Active Directory / LDAP (OPCIONAL) ────────────────────────────────────────────────
# Si LDAP_ENABLED=0 (por defecto) el login es 100% local, como hasta ahora. Si se activa,
# las personas entran con sus credenciales de dominio; PERO el admin local sembrado sigue
# funcionando SIEMPRE como salvavidas (nunca quedarte fuera de tu propio servidor).
LDAP_CONFIG = {
    "enabled":     _env("LDAP_ENABLED", "0") == "1",
    "uri":         _env("LDAP_URI", ""),               # ldaps://dc01.empresa.local:636 (LDAPS)
    "base_dn":     _env("LDAP_BASE_DN", ""),
    "bind_dn":     _env("LDAP_BIND_DN", ""),           # cuenta de servicio de SOLO LECTURA
    "bind_pw":     _env("LDAP_BIND_PW", ""),
    "user_filter": _env("LDAP_USER_FILTER", "(sAMAccountName=%s)"),
    "admin_group": _env("LDAP_ADMIN_GROUP", ""),       # grupo AD -> admin de Hylanlock
    "boss_group":  _env("LDAP_BOSS_GROUP", ""),        # grupo AD -> director (acceso a todo)
    "group_map":   _env("LDAP_GROUP_MAP", ""),         # "GrupoAD:slug:rol, GrupoAD2:slug2:head"
    "tls_cacert":  _env("LDAP_TLS_CACERT", ""),        # CA para validar el certificado del DC
}
LDAP_ENABLED = LDAP_CONFIG["enabled"]

# Avisos por Telegram (opcional, por instalación).
TG_TOKEN = _env("TG_TOKEN", "")
TG_CHAT = _env("TG_CHAT", "")
# ==========================================================================

PART_DIR = os.path.join(DATA_DIR, ".incompletos")     # trozos de subidas a medias (reanudación)
DEPTS_DIR = os.path.join(DATA_DIR, "departamentos")  # base de carpetas de departamento (SOLO LAN)


def dep_dir(slug):
    """Carpeta de un departamento (slug saneado; sin traversal). '' si slug inválido."""
    slug = os.path.basename((slug or "").replace("\\", "/"))
    return os.path.join(DEPTS_DIR, slug) if slug else ""


def sub_dir(dep_slug, sub_slug):
    """Carpeta de una subcarpeta: departamentos/<dep>/<sub>. Ambos slugs saneados (sin traversal).
    '' si cualquiera de los dos no vale."""
    base = dep_dir(dep_slug)
    sub = os.path.basename((sub_slug or "").replace("\\", "/"))
    return os.path.join(base, sub) if (base and sub) else ""

_id_locks = {}
_id_locks_guard = threading.Lock()


def id_lock(upload_id):
    with _id_locks_guard:
        lk = _id_locks.get(upload_id)
        if lk is None:
            lk = threading.Lock()
            _id_locks[upload_id] = lk
        return lk


# --------------------------------------------------- Anti-fuerza-bruta login
_login_fails = {}                 # ip -> [timestamps de fallos recientes]
_login_guard = threading.Lock()


def login_blocked(ip):
    """True si esta IP superó el límite de fallos dentro de la ventana."""
    now = time.time()
    with _login_guard:
        fails = [t for t in _login_fails.get(ip, []) if now - t < LOGIN_WINDOW]
        _login_fails[ip] = fails
        return len(fails) >= LOGIN_MAX_FAILS


def record_login_fail(ip):
    """Registra un fallo y devuelve cuántos lleva en la ventana."""
    now = time.time()
    with _login_guard:
        fails = [t for t in _login_fails.get(ip, []) if now - t < LOGIN_WINDOW]
        fails.append(now)
        _login_fails[ip] = fails
        return len(fails)


def clear_login_fails(ip):
    with _login_guard:
        _login_fails.pop(ip, None)


# ------------------------------------------------------------- Sesión firmada
# La cookie lleva la IDENTIDAD del usuario (usuario|scope|token_version|expira) firmada con HMAC
# usando el secreto persistente del servidor. Sin estado en el servidor; sobrevive reinicios (el
# secreto persiste). El 'token_version' permite REVOCAR las sesiones de un usuario al instante:
# si sube en la BD, las cookies viejas (con el tv anterior) dejan de valer.
def make_session(secret, username, scope, tv, elev=0, rem=0):
    exp = int(time.time()) + SESSION_DAYS * 86400
    payload = f"{username}|{scope}|{tv}|{elev}|{rem}|{exp}"
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}|{sig}".encode()).decode()


def parse_session(secret, value):
    """Devuelve (usuario, scope, token_version, elev_exp, rem) si la firma es válida y no ha expirado.
    'elev_exp' = hasta cuándo la sesión está "elevada" (step-up); 0 = no. 'rem' = 1 si el usuario
    marcó "recordarme" (para conservar la persistencia de la cookie al re-emitirla en el step-up)."""
    try:
        raw = base64.urlsafe_b64decode(value.encode()).decode()
        username, scope, tv, elev, rem, exp, sig = raw.split("|")
        payload = f"{username}|{scope}|{tv}|{elev}|{rem}|{exp}"
        good = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, good):
            return None
        if time.time() > int(exp):
            return None
        return (username, scope, int(tv), int(elev), int(rem))
    except Exception:
        return None


# ------------------------------------------------------------- 2FA: paso intermedio del login
# Tras la contraseña, si la cuenta tiene 2FA, NO se emite la sesión: se emite una cookie corta
# (5 min, solo para /login/2fa) que dice "esta persona ya acertó la contraseña". Va firmada con el
# mismo secreto que la sesión, pero con otro prefijo ("2fa|"), así que nunca sirve como sesión.
TWOFA_PENDING_SECONDS = 300
TWOFA_POLICY_KEY = "require_2fa_admins"


def make_2fa_pending(secret, username, scope, remember):
    exp = int(time.time()) + TWOFA_PENDING_SECONDS
    payload = f"2fa|{username}|{scope}|{1 if remember else 0}|{exp}"
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}|{sig}".encode()).decode()


def parse_2fa_pending(secret, value):
    """(usuario, scope, recordarme) si la cookie intermedia es auténtica y no ha caducado."""
    try:
        raw = base64.urlsafe_b64decode((value or "").encode()).decode()
        tag, username, scope, rem, exp, sig = raw.split("|")
        payload = f"{tag}|{username}|{scope}|{rem}|{exp}"
        good = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if tag != "2fa" or not hmac.compare_digest(sig, good) or time.time() > int(exp):
            return None
        return username, scope, rem == "1"
    except Exception:
        return None


def twofa_cookie(value, secure=False):
    c = f"pr_2fa={value}; Path=/login; SameSite=Strict; HttpOnly; Max-Age={TWOFA_PENDING_SECONDS if value else 0}"
    return c + ("; Secure" if secure else "")


def require_2fa_admins():
    """Política de la organización: ¿los administradores DEBEN tener 2FA?"""
    return db.meta_get(TWOFA_POLICY_KEY, "0") == "1"


# Lo único que puede hacer un admin sin 2FA cuando la política lo exige: ir a activarlo.
TWOFA_SETUP_PATHS = {"/perfil", "/api/perfil", "/api/perfil/tokens", "/perfil/2fa/iniciar",
                     "/perfil/2fa/activar", "/elevate"}


def csrf_token(secret, username, tv):
    """Token anti-CSRF ligado a la sesión (usuario + token_version), sin estado en el servidor.
    Cambia si el usuario cierra en todos (sube tv), invalidando tokens viejos."""
    return hmac.new(secret.encode(), f"{username}|{tv}|csrf".encode(), hashlib.sha256).hexdigest()


def _safe_next(nxt):
    """Solo permite rutas LOCALES como destino de redirección (evita open redirect)."""
    return nxt if (nxt.startswith("/") and not nxt.startswith("//")) else "/admin"


def session_cookie(value, remember, secure=False):
    """Set-Cookie con la sesión firmada. remember=True -> persiste SESSION_DAYS días;
    si no, cookie de sesión (se borra al cerrar el navegador; ideal en PCs compartidos).
    secure=True (servido por HTTPS) añade el flag Secure: el navegador no la manda por HTTP."""
    c = f"pr_token={value}; Path=/; SameSite=Lax; HttpOnly"
    if secure:
        c += "; Secure"
    if remember:
        c += f"; Max-Age={SESSION_DAYS * 86400}"
    return c


def expire_cookie():
    """Set-Cookie que borra la sesión en este navegador (logout)."""
    return "pr_token=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly"


# ------------------------------------------------------------- Avisos Telegram
def notify_telegram(text):
    """Envía un aviso a Telegram (best-effort, en segundo plano, no frena la app)."""
    if not (TG_TOKEN and TG_CHAT):
        return

    def _send():
        try:
            data = urllib.parse.urlencode({"chat_id": TG_CHAT, "text": text}).encode()
            urllib.request.urlopen(
                f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
                data=data, timeout=8)
        except Exception:
            pass
    threading.Thread(target=_send, daemon=True).start()


# ------------------------------------------------------------- Aviso de exposición pública
# Hylanlock es para la red local. Si alguien abre el puerto en el router (o publica el proxy), los
# accesos de fuera ya se rechazan con 403, pero el admin no se entera de que está EXPUESTO. Detección
# PASIVA: si llega una petición desde una IP pública de internet, esa es la prueba. No se consulta
# ningún servicio externo (nada sale de la red). Se recuerdan hasta EXPO_MAX_IPS IPs durante
# EXPO_DAYS días en la tabla meta; el admin ve un banner hasta que pulsa "Revisado", y vuelve a
# salir si aparece una IP NUEVA. Las llamadas a la API con 'remote.access' son remotas a propósito:
# se listan como informativas y no disparan la alarma.
EXPO_KEY, EXPO_ACK_KEY = "exposure_ips", "exposure_ack"
EXPO_MAX_IPS = 50
EXPO_DAYS = 30
_expo_lock = threading.Lock()
_expo_cache = None
_expo_saved = 0.0


def ip_es_publica(ip):
    """True si la IP es de internet (ni privada, ni loopback, ni link-local, ni CGNAT)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    return a.is_global


def _expo_load():
    """Estado en memoria (cargado una vez de meta), sin las IPs de hace más de EXPO_DAYS días."""
    global _expo_cache
    if _expo_cache is None:
        try:
            _expo_cache = json.loads(db.meta_get(EXPO_KEY, "") or "{}")
        except (ValueError, TypeError):
            _expo_cache = {}
    corte = time.time() - EXPO_DAYS * 86400
    for ip in [ip for ip, e in _expo_cache.items() if e.get("last", 0) < corte]:
        del _expo_cache[ip]
    return _expo_cache


def exposure_note(ip, path, legit=False):
    """Registra una petición llegada desde internet. Barato para la LAN (sale en la 1ª línea)."""
    global _expo_saved
    if not ip_es_publica(ip):
        return
    now = time.time()
    with _expo_lock:
        data = _expo_load()
        e = data.get(ip)
        nueva = e is None
        if nueva:
            if len(data) >= EXPO_MAX_IPS:
                del data[min(data, key=lambda k: data[k].get("last", 0))]
            e = data[ip] = {"first": now, "last": 0, "count": 0, "path": "", "legit": legit}
        dia_nuevo = time.strftime("%Y-%m-%d", time.localtime(e["last"])) != time.strftime("%Y-%m-%d")
        e["count"] += 1
        e["last"] = now
        e["path"] = path[:120]
        e["legit"] = e["legit"] and legit      # basta UN acceso no autorizado para que cuente
        if nueva or dia_nuevo or now - _expo_saved > 60:
            try:
                db.meta_set(EXPO_KEY, json.dumps(data))
                _expo_saved = now
            except Exception:
                pass
    if nueva or dia_nuevo:                      # auditoría: una vez por IP y día, sin inundar
        db.log_event("public_access", origin="remoto", ip=ip,
                     detail=("API remota autorizada: " if legit else "") + path[:120])
    if nueva and not legit:
        print(f"  [AVISO] conexión desde INTERNET: {ip} -> {path[:80]}. {brand_name()} es para la red "
              f"local: revisa el router/proxy.", flush=True)
        notify_telegram(f"⚠️ {brand_name()}: conexión desde internet ({ip} -> {path[:80]}).\n"
                        "Está pensado para la red local: revisa el router o el proxy.")


def exposure_state():
    """(lista de IPs más recientes primero, nº de IPs NO autorizadas aparecidas tras el último 'Revisado')."""
    with _expo_lock:
        data = {ip: dict(e) for ip, e in _expo_load().items()}
    try:
        ack = float(db.meta_get(EXPO_ACK_KEY, "0") or 0)
    except ValueError:
        ack = 0.0
    filas = sorted(({"ip": ip, **e} for ip, e in data.items()), key=lambda x: -x["last"])
    pendientes = sum(1 for f in filas if not f["legit"] and f["first"] > ack)
    return filas, pendientes


def _hace(ts):
    """'hace 5 min', 'hace 3 h', 'hace 2 d' (para avisos)."""
    d = max(0, time.time() - (ts or 0))
    if d < 60:
        return "hace un momento"
    if d < 3600:
        return f"hace {int(d // 60)} min"
    if d < 86400:
        return f"hace {int(d // 3600)} h"
    return f"hace {int(d // 86400)} d"


def lan_cidrs_publicas():
    """Subredes de HYLANLOCK_LAN_CIDR que incluyen IPs de internet (error de configuración grave:
    haría que internet 'pareciera' red local)."""
    cgnat = ipaddress.ip_network("100.64.0.0/10")
    return [str(n) for n in _LAN_NETS
            if not (n.is_private or n.is_loopback or n.is_link_local
                    or (n.version == 4 and n.subnet_of(cgnat)))]


# ------------------------------------------------------------- Gobernanza (gestionar sin leer)
# El explorador de gobernanza enseña a quien tenga 'folder.oversee' (admins y rol Supervisor) la
# estructura de TODAS las carpetas: tamaños, antigüedad, quién tiene acceso, actividad, duplicados.
# Nunca el contenido ni el NOMBRE de un archivo ('despido-juan.pdf' ya es un dato personal): los
# nombres solo se usan aquí, en el servidor, para cruzarlos con la auditoría, y no salen de esta
# función. Cada archivo se identifica por su tipo, tamaño, fecha y huella SHA-256 corta.
GOV_STALE_DAYS = 90      # carpeta "sin movimiento" si no hay archivos nuevos ni actividad en N días
GOV_OLD_DAYS = 365       # archivo "antiguo"
GOV_MAX_FILES = 500      # filas de detalle por carpeta (los totales cuentan todo)


def _gov_ts(s):
    """'YYYY-MM-DD HH:MM:SS' (hora local de la auditoría) -> epoch. None si no se puede."""
    try:
        return time.mktime(time.strptime(s, "%Y-%m-%d %H:%M:%S"))
    except (TypeError, ValueError):
        return None


def _gov_hash(path):
    """Huella SHA-256 guardada al subir (sidecar). No se recalcula: leer GB de disco por una vista no."""
    try:
        with open(path + SHA_EXT, encoding="utf-8") as f:
            h = f.read(64)
        return h if len(h) == 64 and all(ch in "0123456789abcdef" for ch in h) else None
    except OSError:
        return None


def _gov_folder(path, tag, activity, files_meta, now):
    filas = []
    try:
        nombres = os.listdir(path)
    except OSError:
        nombres = []
    for name in nombres:
        if name.endswith(SHA_EXT):
            continue
        p = os.path.join(path, name)
        try:
            if not os.path.isfile(p):
                continue                      # las subcarpetas se listan aparte
            st = os.stat(p)
        except OSError:
            continue
        meta = files_meta.get((tag, name), {})
        filas.append({"ext": (os.path.splitext(name)[1].lower().lstrip(".")[:10] or ""),
                      "size": st.st_size, "mtime": st.st_mtime, "by": meta.get("by"),
                      "downloads": meta.get("downloads", 0), "hash": _gov_hash(p)})
    filas.sort(key=lambda f: -f["mtime"])
    act = activity.get(tag)
    last = {"ts": _gov_ts(act["ts"]), "type": act["type"], "user": act["user"]} if act else None
    newest = max((f["mtime"] for f in filas), default=None)
    movimiento = max([t for t in (newest, last and last["ts"]) if t] or [0])
    return {"count": len(filas), "size": sum(f["size"] for f in filas),
            "newest": newest, "oldest": min((f["mtime"] for f in filas), default=None),
            "old_files": sum(1 for f in filas if f["mtime"] < now - GOV_OLD_DAYS * 86400),
            "stale": bool(filas) and movimiento < now - GOV_STALE_DAYS * 86400,
            "last": last, "files": filas[:GOV_MAX_FILES], "_all": filas}


def governance_snapshot():
    """Foto de gobernanza de todas las carpetas, SIN nombres de archivo."""
    now = time.time()
    activity, files_meta = db.folder_activity()
    usuarios = db.list_users()
    globales = sorted(u["username"] for u in usuarios
                      if u["scope"] == "admin" or (u["boss"] and u["scope"] != "service"))
    supervisores = sorted(u["username"] for u in usuarios if u.get("supervisor"))
    deps, todas = [], []
    for d in db.list_departments():
        slug = d["slug"]
        dep = _gov_folder(dep_dir(slug), db.folder_tag(slug), activity, files_meta, now)
        dep.update({"name": d["name"], "slug": slug, "access": db.department_members(slug), "subs": []})
        todas.append(dep)
        for s in db.list_subfolders(slug):
            sub = _gov_folder(sub_dir(slug, s["slug"]), db.folder_tag(slug, s["slug"]),
                              activity, files_meta, now)
            sub.update({"name": s["name"], "slug": s["slug"], "access": db.subfolder_acl(slug, s["slug"]),
                        "buzones": len(db.list_buzon_links(slug, s["slug"]))})
            dep["subs"].append(sub)
            todas.append(sub)
        deps.append(dep)
    # Duplicados: mismo contenido (misma huella) guardado en más de un sitio.
    por_hash = {}
    for carpeta in todas:
        for f in carpeta["_all"]:
            if f["hash"]:
                por_hash.setdefault(f["hash"], []).append(f["size"])
    copias = [sizes for sizes in por_hash.values() if len(sizes) > 1]
    dups = {h for h, sizes in por_hash.items() if len(sizes) > 1}
    for carpeta in todas:
        for f in carpeta["files"]:
            f["dup"] = f["hash"] in dups
            f["hash"] = f["hash"][:12] if f["hash"] else None
        del carpeta["_all"]
    papelera = db.trash_list()
    kpi = {"trash": len(papelera), "trash_bytes": sum(t["size"] or 0 for t in papelera),
           "deps": len(deps), "subs": len(todas) - len(deps),
           "files": sum(c["count"] for c in todas), "size": sum(c["size"] for c in todas),
           "empty": sum(1 for c in todas if not c["count"]),
           "stale": sum(1 for c in todas if c["stale"]),
           "old_files": sum(c["old_files"] for c in todas),
           "dup_copies": sum(len(s) - 1 for s in copias),
           "dup_bytes": sum(sum(s) - s[0] for s in copias)}
    return {"generated": now, "stale_days": GOV_STALE_DAYS, "old_days": GOV_OLD_DAYS,
            "max_files": GOV_MAX_FILES, "kpi": kpi, "global_access": globales,
            "supervisors": supervisores, "deps": deps}


def _origin_label(origin):
    return "red local" if origin == "local" else "remoto"


def enable_ansi_colors():
    # Consola en UTF-8: evita que el banner (caracteres de caja ═║) tumbe la app en
    # una consola Windows con codepage cp1252 al arrancar.
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8")
        except Exception:
            pass
    if os.name == "nt":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            pass


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def human_size(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


# ------------------------------------------------------------------ Integridad (SHA-256)
SHA_EXT = ".sha256"       # extensión del fichero de comprobación (formato de sha256sum)


def sha256_file(path):
    """SHA-256 (hex) de un archivo, leyendo por trozos (no carga todo en memoria)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(CHUNK_READ), b""):
            h.update(block)
    return h.hexdigest()


def write_sidecar_hash(path, digest):
    """Escribe '<hash> *<archivo>' junto al fichero (compatible con 'sha256sum -c')."""
    try:
        # newline="" -> fin de línea Unix (\n) también en Windows, para que
        # 'sha256sum -c' funcione en Linux sin ver un \r pegado al nombre.
        with open(path + SHA_EXT, "w", encoding="utf-8", newline="") as f:
            f.write(f"{digest} *{os.path.basename(path)}\n")
    except OSError:
        pass


# ── Paginación de listados ──────────────────────────────────────────────────────────────────
# Tamaños de página de la API. El máximo existe para que una integración no pueda pedir "todo"
# y tumbar el servidor con una sola llamada.
API_PAGE_DEFAULT = 500
API_PAGE_MAX = 1000
# Tope de ficheros POR CARPETA dentro del manifiesto de sincronización. Lo que pase de ahí se
# marca como recortado y el cliente lo completa con /api/v1/files.
MANIFEST_FILES_PER_FOLDER = 500


def _cursor_encode(mtime, name):
    """Cursor opaco a propósito: es la CLAVE de orden (fecha, nombre) del último elemento servido.

    Va codificado para que nadie construya uno a mano ni dependa de su formato: así se puede
    cambiar la implementación sin romper a quien lo esté usando."""
    crudo = json.dumps([mtime, name], separators=(",", ":"))
    return base64.urlsafe_b64encode(crudo.encode("utf-8")).decode("ascii").rstrip("=")


def _cursor_decode(cursor):
    """Devuelve la clave de orden (-mtime, name), o None si el cursor no vale.

    Un cursor inválido NO es un error: se trata como 'empieza por el principio'. Es preferible a
    devolver un 400 por un cursor caducado o mal copiado."""
    if not cursor:
        return None
    try:
        relleno = "=" * (-len(cursor) % 4)
        mtime, name = json.loads(
            base64.urlsafe_b64decode(cursor + relleno).decode("utf-8"))
        return (-float(mtime), str(name))
    except Exception:
        return None


def _pagina_pedida(query):
    """Lee y acota el tamaño de página que pide el cliente."""
    try:
        limit = int(query.get("limit", [API_PAGE_DEFAULT])[0])
    except (ValueError, TypeError):
        limit = API_PAGE_DEFAULT
    return max(1, min(limit, API_PAGE_MAX))


# ── Especificación OpenAPI del contrato público ─────────────────────────────────────────────
# Versión del CONTRATO, no del producto: sube solo si cambia lo que /api/v1 promete.
API_CONTRACT_VERSION = "1.0"


def openapi_spec():
    """Documento OpenAPI 3.1 de `/api/v1`, generado aquí mismo.

    Se escribe a mano y en el mismo fichero que los handlers a propósito: es un contrato pequeño y
    estable, y tenerlo al lado del código es lo que evita que se separe de la realidad. Nada de
    generarlo con una librería — el producto no tiene dependencias y no va a empezar por esto.

    Se sirve desde el propio servidor para que una integración pueda descubrir la API sin salir de
    la red de la empresa ni buscar documentación por ahí fuera.
    """
    error = {
        "type": "object",
        "properties": {
            "error": {"type": "string",
                      "description": "Código estable: bad_request, unauthorized, forbidden, "
                                     "not_found, rate_limited, payload_too_large, server_error."},
            "message": {"type": "string", "description": "Explicación para humanos. Puede cambiar."},
        },
        "required": ["error", "message"],
    }
    fichero = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "size": {"type": "integer", "description": "Tamaño en bytes."},
            "mtime": {"type": "number", "description": "Fecha de modificación (epoch)."},
            "sha256": {"type": "string",
                       "description": "Hash del contenido. Vacío si el archivo se dejó "
                                      "directamente en la carpeta del servidor y no tiene "
                                      "fichero de comprobación al lado."},
        },
        "required": ["name", "size", "mtime", "sha256"],
    }
    carpeta = {
        "type": "object",
        "properties": {
            "kind": {"type": "string", "enum": ["department", "subfolder"]},
            "path": {"type": "string", "description": "'departamento' o 'departamento/subcarpeta'."},
            "name": {"type": "string"},
            "department": {"type": "string"},
            "can_download": {"type": "boolean"},
        },
        "required": ["kind", "path", "name"],
    }

    def respuesta(descr, esquema):
        return {"description": descr,
                "content": {"application/json": {"schema": esquema}}}

    def errores(*codigos):
        return {str(c): respuesta(t, {"$ref": "#/components/schemas/Error"})
                for c, t in codigos}

    comunes = (401, "Sin credenciales o credenciales inválidas."), \
              (403, "Fuera de la red local, o sin permiso sobre esa carpeta."), \
              (429, f"Más de {API_RATE_LIMIT} peticiones por minuto con la misma clave.")

    param_folder = {"name": "folder", "in": "query", "required": True,
                    "schema": {"type": "string"},
                    "description": "'departamento' o 'departamento/subcarpeta'."}

    return {
        "openapi": "3.1.0",
        "info": {
            "title": f"{ORG_NAME} — API",
            "version": API_CONTRACT_VERSION,
            "description": (
                "Contrato público de Hylanlock. **Solo `/api/v1/*` es estable**: el resto de "
                "`/api/*` es el backend interno de las pantallas y puede cambiar sin aviso.\n\n"
                "La API vive **dentro de la red local** de la empresa. Una cuenta de servicio "
                "puede salir de esa red si se le concede el permiso de acceso remoto, y ese "
                "permiso solo afecta a `/api/v1`: la web sigue siendo solo-LAN para todos.\n\n"
                "**No hay borrado por API**, y es deliberado: los datos del cliente no se "
                "destruyen desde fuera."),
        },
        "servers": [{"url": "/", "description": "El propio servidor de Hylanlock."}],
        "security": [{"bearerAuth": []}],
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http", "scheme": "bearer",
                    "description": "Clave de una cuenta de servicio: "
                                   "`Authorization: Bearer <clave>`. Sus permisos son los del "
                                   "RBAC de siempre; no puede entrar por la web.",
                },
            },
            "schemas": {"Error": error, "File": fichero, "Folder": carpeta},
        },
        "paths": {
            "/api/v1/whoami": {
                "get": {
                    "summary": "Quién soy y a qué llego",
                    "description": "Existe para que integrar sea depurable: «¿por qué no veo esa "
                                   "carpeta?» se responde con una llamada.",
                    "responses": dict(**{"200": respuesta("Identidad y carpetas visibles", {
                        "type": "object",
                        "properties": {
                            "user": {"type": "string"},
                            "kind": {"type": "string", "enum": ["service", "person"]},
                            "auth": {"type": "string", "enum": ["token", "session"]},
                            "remote_allowed": {"type": "boolean"},
                            "folders": {"type": "array", "items": {"type": "string"}},
                        }})}, **errores(*comunes)),
                },
            },
            "/api/v1/folders": {
                "get": {
                    "summary": "Carpetas a las que llega esta clave",
                    "description": "Una carpeta donde solo puedes DEJAR archivos (buzón de "
                                   "entrega) no aparece aquí: no puedes listarla, así que para "
                                   "la API de lectura no existe.",
                    "responses": dict(**{"200": respuesta("Listado de carpetas", {
                        "type": "object",
                        "properties": {"folders": {"type": "array",
                                                   "items": {"$ref": "#/components/schemas/Folder"}}}
                    })}, **errores(*comunes)),
                },
            },
            "/api/v1/files": {
                "get": {
                    "summary": "Archivos de una carpeta (paginado)",
                    "description": (
                        "**Comprueba siempre `has_more`.** Si lo ignoras y la carpeta tiene más "
                        "archivos que el tamaño de página, te llevarás una parte creyendo que la "
                        "tienes entera.\n\nEl `cursor` es opaco: es la posición del último "
                        "elemento servido, codificada. No lo construyas a mano. Al basarse en la "
                        "posición y no en un número de página, borrar archivos mientras paginas "
                        "no hace que te saltes otros."),
                    "parameters": [
                        param_folder,
                        {"name": "limit", "in": "query", "required": False,
                         "schema": {"type": "integer", "default": API_PAGE_DEFAULT,
                                    "minimum": 1, "maximum": API_PAGE_MAX},
                         "description": "Tamaño de página. Fuera de rango se ajusta al tope."},
                        {"name": "cursor", "in": "query", "required": False,
                         "schema": {"type": "string"},
                         "description": "El 'next' de la respuesta anterior. Un cursor inválido "
                                        "no da error: se empieza por el principio."},
                    ],
                    "responses": dict(**{"200": respuesta(
                        "Página de archivos, por fecha descendente", {
                            "type": "object",
                            "properties": {
                                "folder": {"type": "string"},
                                "files": {"type": "array",
                                          "items": {"$ref": "#/components/schemas/File"}},
                                "has_more": {"type": "boolean"},
                                "next": {"type": "string",
                                         "description": "Solo si has_more es true."},
                            }})},
                        **errores((400, "Falta 'folder' o no tiene forma válida."), *comunes)),
                },
            },
            "/api/v1/download": {
                "get": {
                    "summary": "Descargar un archivo",
                    "description": "Devuelve la cabecera **X-Content-SHA256** para comprobar la "
                                   "integridad, y admite descarga por rangos (Range).",
                    "parameters": [
                        param_folder,
                        {"name": "file", "in": "query", "required": True,
                         "schema": {"type": "string"}, "description": "Nombre del archivo."},
                    ],
                    "responses": dict(**{
                        "200": {"description": "El archivo",
                                "headers": {"X-Content-SHA256": {
                                    "schema": {"type": "string"},
                                    "description": "SHA-256 del contenido servido."}},
                                "content": {"application/octet-stream":
                                            {"schema": {"type": "string", "format": "binary"}}}},
                        "206": {"description": "Parte del archivo (petición con Range)."},
                    }, **errores((400, "Falta 'folder' o 'file'."),
                                 (404, "El archivo no existe en esa carpeta."), *comunes)),
                },
            },
            "/api/v1/upload": {
                "post": {
                    "summary": "Subir un archivo en una sola petición",
                    "description": (
                        "El cuerpo **es** el archivo, sin envoltorio. Requiere permiso de subida "
                        "sobre esa carpeta.\n\nEsta es la única vía de escritura con clave: un "
                        "POST con token a cualquier ruta que no sea `/api/v1/*` se rechaza. Y la "
                        "exención de CSRF que lo hace posible se aplica **solo si la petición NO "
                        "trae una sesión de cookie válida**."),
                    "parameters": [
                        param_folder,
                        {"name": "name", "in": "query", "required": True,
                         "schema": {"type": "string"},
                         "description": "Nombre con el que se guardará."},
                        {"name": "X-SHA256", "in": "header", "required": False,
                         "schema": {"type": "string"},
                         "description": "SHA-256 esperado. Si se envía y no coincide con lo "
                                        "recibido, la subida se descarta."},
                    ],
                    "requestBody": {"required": True, "content": {
                        "application/octet-stream": {
                            "schema": {"type": "string", "format": "binary"}}}},
                    "responses": dict(**{"201": respuesta("Archivo guardado", {
                        "type": "object",
                        "properties": {"folder": {"type": "string"}, "name": {"type": "string"},
                                       "size": {"type": "integer"},
                                       "sha256": {"type": "string"}}})},
                        **errores((400, "Faltan parámetros, o el SHA-256 no coincide."),
                                  (413, "El archivo supera el tamaño máximo admitido."),
                                  *comunes)),
                },
            },
            "/api/v1/sync/manifest": {
                "get": {
                    "summary": "Todas las carpetas con sus archivos, en una llamada",
                    "description": (
                        "Atajo masivo que usa el agente de sincronización. Cada carpeta trae como "
                        "mucho unos cientos de archivos; a la que le falten viene marcada con "
                        "`truncated` y un `next` con el que **completarla** por `/api/v1/files`."
                        "\n\n**Si sincronizas borrados, esto es crítico**: tratar una "
                        "respuesta recortada como si fuera completa lleva a concluir que los "
                        "archivos que faltan han desaparecido del servidor."),
                    "responses": dict(**{"200": respuesta("Manifiesto", {
                        "type": "object",
                        "properties": {
                            "user": {"type": "string"},
                            "generated_at": {"type": "string"},
                            "truncated": {"type": "boolean",
                                          "description": "Falta algo por pedir en alguna carpeta."},
                            "folders": {"type": "array", "items": {
                                "type": "object",
                                "properties": {
                                    "path": {"type": "string"},
                                    "name": {"type": "string"},
                                    "download_url": {"type": "string"},
                                    "files": {"type": "array",
                                              "items": {"$ref": "#/components/schemas/File"}},
                                    "truncated": {"type": "boolean"},
                                    "next": {"type": "string"},
                                }}},
                        }})}, **errores(*comunes)),
                },
            },
            "/api/v1/openapi.json": {
                "get": {"summary": "Esta misma especificación",
                        "responses": {"200": respuesta("Documento OpenAPI 3.1",
                                                       {"type": "object"})}},
            },
        },
    }


def read_sidecar_hash(path):
    """Lee el SHA-256 guardado junto al fichero, o '' si no existe."""
    try:
        with open(path + SHA_EXT, encoding="utf-8") as f:
            return f.read().strip().split(" ", 1)[0].lower()
    except OSError:
        return ""


def safe_id(raw):
    """Solo permite letras/numeros/-/_ en el id de subida (nombre de archivo .part)."""
    keep = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    return "".join(c for c in (raw or "") if c in keep)[:80]


def safe_username(raw):
    """Nombre de usuario seguro: letras/numeros/-/_/. , max 32."""
    keep = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
    return "".join(c for c in (raw or "").strip() if c in keep)[:32]


def safe_relpath(name):
    """Convierte una ruta relativa recibida en segmentos seguros (sin traversal)."""
    name = (name or "").replace("\\", "/")
    bad = '<>:"|?*'
    parts = []
    for seg in name.split("/"):
        seg = seg.strip()
        if seg in ("", ".", ".."):
            continue
        seg = "".join(c for c in seg if c not in bad and ord(c) >= 32)
        seg = seg.rstrip(" .")
        if seg:
            parts.append(seg)
    return parts or ["archivo"]


def unique_path(folder, filename):
    filename = os.path.basename(filename.replace("\\", "/")).strip() or "archivo"
    base, ext = os.path.splitext(filename)
    candidate = os.path.join(folder, filename)
    i = 1
    while os.path.exists(candidate):
        candidate = os.path.join(folder, f"{base} ({i}){ext}")
        i += 1
    return candidate


# ── Bloqueo de extensiones peligrosas (HIGIENE, no antivirus) ────────────────────────────────
# Rechaza subir ejecutables/scripts que alguien podría abrir por error y "cagarla" (un .exe que
# llega disfrazado en un buzón, etc.). Es una capa de HIGIENE/accidentes, NO un antivirus:
# renombrar la extensión lo salta. Se aplica en la web, la API y el agente de sincronización.
# El admin puede ajustar la lista con HYLANLOCK_BLOCKED_EXT (separada por comas, REEMPLAZA la de
# por defecto; ponerla vacía DESACTIVA el bloqueo).
_BLOCKED_EXT_DEFAULT = ("exe,bat,cmd,com,scr,pif,msi,msp,cpl,jar,js,jse,vbs,vbe,"
                        "wsf,wsh,hta,ps1,psm1,sh,reg,lnk,inf,dll,sys,scf,msc")
def _parse_ext(texto):
    """Lista separada por comas -> conjunto de extensiones normalizadas (minúsculas, sin punto)."""
    return frozenset(e.strip().lower().lstrip(".") for e in (texto or "").split(",") if e.strip())


# Valor por DEFECTO (del .env o la constante). Es la SEMILLA: si el admin no ha guardado nada
# desde el panel, se usa esto.
BLOCKED_EXT = _parse_ext(_env("BLOCKED_EXT", _BLOCKED_EXT_DEFAULT))

# Caché de la lista EFECTIVA (default, o lo que el admin guardó en el panel). Se invalida al guardar.
_blocked_cache = None


def blocked_ext_set():
    """Lista de bloqueo EFECTIVA: lo guardado en el panel (meta 'blocked_ext') si existe; si no, el
    valor por defecto del .env. Cacheada; se refresca con set_blocked_ext()."""
    global _blocked_cache
    if _blocked_cache is None:
        guardado = db.meta_get("blocked_ext")      # None = nunca tocado desde el panel
        _blocked_cache = BLOCKED_EXT if guardado is None else _parse_ext(guardado)
    return _blocked_cache


def set_blocked_ext(texto):
    """Guarda la lista (desde el panel) y refresca la caché. Texto vacío = desactivar el bloqueo."""
    global _blocked_cache
    db.meta_set("blocked_ext", texto or "")
    _blocked_cache = _parse_ext(texto)
    return _blocked_cache


# ── Marca blanca EFECTIVA: lo guardado en Ajustes (tabla meta) o el valor de fábrica/entorno ──
def brand_name():
    v = db.meta_get("brand_name")
    return v.strip() if v and v.strip() else BRAND_NAME


def brand_logo():
    # None = nunca configurado -> entorno; "" = configurado a vacío -> candado por defecto.
    v = db.meta_get("brand_logo")
    return BRAND_LOGO if v is None else v


def brand_accent():
    v = db.meta_get("accent")
    return ((v if v is not None else ACCENT) or "").strip()


def set_branding(name=None, logo=None, accent=None):
    """Guarda la marca blanca en meta. Cada campo None = no se toca. Se aplica en toda la interfaz."""
    if name is not None:
        db.meta_set("brand_name", name.strip()[:40])
    if logo is not None:
        db.meta_set("brand_logo", logo.strip()[:8])
    if accent is not None:
        db.meta_set("accent", accent.strip()[:9])


def extension_bloqueada(nombre):
    """Devuelve la extensión (sin punto) si está en la lista de bloqueo EFECTIVA, o '' si se permite.

    Mira SOLO la última extensión, que es la que decide cómo se abre el archivo:
    'factura.pdf.exe' -> 'exe' (bloqueada); 'notas.exe.txt' -> 'txt' (permitida)."""
    ext = os.path.splitext(nombre or "")[1].lower().lstrip(".")
    return ext if ext in blocked_ext_set() else ""


# Cada cuánto se vuelve a barrer la carpeta de trozos incompletos mientras el servicio corre.
PART_PURGE_EVERY = 3600           # 1 h
_last_purge = 0.0
_purge_lock = threading.Lock()


def purge_old_parts_if_due():
    """Purga con puerta de tiempo: llamable en caliente sin coste apreciable.

    Hace falta porque `/upload/chunk` NO puede comprobar el permiso del destino — el destino
    (departamento o subcarpeta) se decide después, en `/upload/complete`. Así que el trozo se
    escribe SIEMPRE y solo luego se deniega, y ese `.part` se queda huérfano. Purgar solo al
    arrancar dejaba crecer `.incompletos` sin límite en un servidor encendido durante meses."""
    global _last_purge
    now = time.time()
    if now - _last_purge < PART_PURGE_EVERY:
        return
    with _purge_lock:
        if now - _last_purge < PART_PURGE_EVERY:      # otro hilo se nos adelantó
            return
        _last_purge = now
    purge_old_parts()


# ------------------------------------------------------------------ Papelera (borrado blando)
# "Nunca destruir datos en silencio": borrar MUEVE el archivo (y su .sha256) a <DATA_DIR>/.papelera/<id>/,
# fuera de las carpetas visibles, y apunta de dónde venía. Solo los administradores borran, restauran y
# eliminan (decisión de Nicolás, 16-oct). Pasados TRASH_DAYS días se elimina de verdad (0 = nunca), y
# todo queda en la auditoría. Restaurar lo devuelve a su carpeta original, sin pisar nada.
TRASH_DIR = os.path.join(DATA_DIR, ".papelera")
TRASH_KEY = "trash_days"
TRASH_DEFAULT_DAYS = 30
TRASH_PURGE_EVERY = 3600
_last_trash_purge = 0.0


def trash_days():
    try:
        return max(0, int(db.meta_get(TRASH_KEY, str(TRASH_DEFAULT_DAYS)) or TRASH_DEFAULT_DAYS))
    except ValueError:
        return TRASH_DEFAULT_DAYS


def _folder_dir(dep, sub=None):
    """Carpeta real de un departamento o subcarpeta EXISTENTE, o '' si no existe."""
    if not any(d["slug"] == dep for d in db.list_departments()):
        return ""
    if sub and not any(x["slug"] == sub for x in db.list_subfolders(dep)):
        return ""
    return sub_dir(dep, sub) if sub else dep_dir(dep)


def move_to_trash(dep, sub, name, who):
    """Manda un archivo a la papelera. Devuelve (id, None) o (None, 'motivo')."""
    folder = _folder_dir(dep, sub)
    name = os.path.basename((name or "").replace("\\", "/"))
    src = os.path.join(folder, name) if folder and name else ""
    if not src or name.endswith(SHA_EXT) or not os.path.isfile(src):
        return None, "Ese archivo no existe en esta carpeta."
    size = os.path.getsize(src)
    item = db.trash_add(dep, sub, name, size, read_sidecar_hash(src) or None, who)
    dest_dir = os.path.join(TRASH_DIR, str(item))
    try:
        os.makedirs(dest_dir, exist_ok=True)
        os.replace(src, os.path.join(dest_dir, name))
    except OSError as e:
        db.trash_remove(item)
        return None, f"No se pudo mover a la papelera: {e}"
    if os.path.exists(src + SHA_EXT):
        try:
            os.replace(src + SHA_EXT, os.path.join(dest_dir, name + SHA_EXT))
        except OSError:
            pass
    return item, None


def restore_from_trash(item_id):
    """Devuelve un archivo a su carpeta original. (nombre_final, None) o (None, 'motivo')."""
    it = db.trash_get(item_id)
    if not it:
        return None, "No está en la papelera."
    folder = _folder_dir(it["dept_slug"], it["sub_slug"])
    if not folder:
        return None, "La carpeta original ya no existe: vuelve a crearla y restaura después."
    src = os.path.join(TRASH_DIR, str(item_id), it["name"])
    if not os.path.isfile(src):
        return None, "El archivo ya no está en la papelera (¿se eliminó a mano del disco?)."
    os.makedirs(folder, exist_ok=True)
    dest = unique_path(folder, it["name"])      # nunca pisa un archivo que exista con ese nombre
    os.replace(src, dest)
    if it["sha256"]:
        write_sidecar_hash(dest, it["sha256"])  # el .sha256 lleva el nombre: se reescribe por si cambió
    _trash_rmdir(item_id)
    db.trash_remove(item_id)
    return os.path.basename(dest), None


def purge_trash_item(item_id):
    """Elimina DE VERDAD un elemento de la papelera. Devuelve el registro o None."""
    it = db.trash_get(item_id)
    if not it:
        return None
    _trash_rmdir(item_id)
    db.trash_remove(item_id)
    return it


def _trash_rmdir(item_id):
    d = os.path.join(TRASH_DIR, str(int(item_id)))
    try:
        for f in os.listdir(d):
            os.remove(os.path.join(d, f))
        os.rmdir(d)
    except OSError:
        pass


def trash_purge_expired():
    """Vaciado automático: elimina lo que lleva más de trash_days() días (0 = nunca)."""
    days = trash_days()
    if not days:
        return 0
    n = 0
    for item_id in db.trash_older_than(days):
        it = purge_trash_item(item_id)
        if it:
            n += 1
            db.log_event("trash_autopurge", user="sistema", origin="local",
                         detail=f"{db.folder_tag(it['dept_slug'], it['sub_slug'])}{it['name']} "
                                f"(más de {days} días en la papelera)", bytes=it["size"])
    return n


def trash_purge_if_due():
    """Con puerta de tiempo (como los trozos incompletos): barato de llamar en cada petición."""
    global _last_trash_purge
    now = time.time()
    if now - _last_trash_purge < TRASH_PURGE_EVERY:
        return
    with _purge_lock:
        if now - _last_trash_purge < TRASH_PURGE_EVERY:
            return
        _last_trash_purge = now
    try:
        trash_purge_expired()
    except Exception as e:      # nunca tumbar una petición por la limpieza
        print(f"  [papelera] error en el vaciado automático: {e}", flush=True)


def purge_old_parts():
    import time
    now = time.time()
    try:
        for name in os.listdir(PART_DIR):
            p = os.path.join(PART_DIR, name)
            try:
                if os.path.isfile(p) and now - os.path.getmtime(p) > PART_MAX_AGE:
                    os.remove(p)
            except OSError:
                pass
    except OSError:
        pass


def incompletos_total_bytes():
    """Suma el tamaño de los trozos incompletos en disco. Para el tope de `.incompletos` (H1)."""
    total = 0
    try:
        with os.scandir(PART_DIR) as it:
            for e in it:
                try:
                    if e.is_file():
                        total += e.stat().st_size
                except OSError:
                    pass
    except OSError:
        pass
    return total


# ------------------------------------------------------------------ Plantillas web (HTML/CSS)
# El HTML y el CSS viven en la carpeta web/ (una plantilla por archivo). Aqui solo van los
# NOMBRES de archivo; render() los carga y sustituye los marcadores __CSS__, __SLUG__, etc.
# En produccion se cachean; con HYLANLOCK_DEV=1 se releen en cada peticion (edicion en vivo).
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
DEV_MODE = _env("DEV", "").lower() not in ("", "0", "false", "no")
_tpl_cache = {}


def _template(name):
    """Lee web/<name>. Cachea salvo en modo DEV (relee para editar sin reiniciar)."""
    if not DEV_MODE and name in _tpl_cache:
        return _tpl_cache[name]
    with open(os.path.join(WEB_DIR, name), encoding="utf-8") as f:
        txt = f.read()
    _tpl_cache[name] = txt
    return txt


CSS            = "styles.css"
LAYOUT_PAGE    = "layout.html"      # shell compartido (sidebar + área de contenido)
PROFILE_PAGE   = "profile.html"     # perfil del usuario: sus permisos + solicitar acceso
PAPELERA_PAGE  = "papelera.html"    # papelera (solo admins)
GOBERNANZA_PAGE = "gobernanza.html"  # explorador de gobernanza (gestionar sin leer)
AJUSTES_PAGE   = "ajustes.html"     # configuración general: tema, idioma, plan, acerca de
LOGIN_PAGE     = "login.html"
WELCOME_PAGE   = "welcome.html"     # home: pantalla de bienvenida
ACTIVATE_PAGE  = "activate.html"    # pantalla pública: activar cuenta / poner contraseña
BUZON_PAGE     = "buzon.html"       # pantalla pública: dejar un archivo por enlace de buzón
SETUP_PAGE     = "setup.html"       # asistente de primer arranque (crear admin + licencia)
BLOCKED_PAGE   = "blocked.html"     # pantalla de bloqueo cuando la licencia no es válida
LICENSE_PAGE   = "license.html"     # pantalla de admin: estado de licencia + instalar nueva
DEP_PAGE       = "departamento.html"
DEPTS_PAGE     = "departamentos.html"
ADMIN_PAGE     = "admin.html"
LOG_PAGE       = "log.html"
STEPUP_PAGE    = "elevate.html"
TWOFA_PAGE     = "twofa.html"       # segundo paso del login (código del móvil)


# Interruptor de tema claro/oscuro, inyectado en todas las páginas.
# El <head> aplica el tema guardado ANTES de pintar (sin parpadeo); el botón lo cambia.
_THEME_HEAD = ('<script>(function(){try{var t=localStorage.getItem("hyl-theme");'
               'if(t)document.documentElement.setAttribute("data-theme",t);}catch(e){}})();</script>')
# Icono ESTÁTICO de "cambiar tema" (contraste): no cambia de forma, solo alterna el tema al pulsar.
_THEME_TOGGLE = (
    '<button type="button" id="hyl-theme-btn" aria-label="Cambiar tema claro/oscuro" '
    'onclick="(function(){var r=document.documentElement,'
    "c=r.getAttribute('data-theme')||(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'),"
    "n=c==='dark'?'light':'dark';r.setAttribute('data-theme',n);"
    "try{localStorage.setItem('hyl-theme',n);}catch(e){}})()\">"
    '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" '
    'stroke-width="2"><circle cx="12" cy="12" r="9"/>'
    '<path d="M12 3a9 9 0 0 1 0 18z" fill="currentColor" stroke="none"/></svg></button>')


def _valid_hex(c):
    """True si c es un color hex tipo #rgb / #rrggbb / #rrggbbaa (evita inyectar CSS arbitrario)."""
    return (c.startswith("#") and len(c) in (4, 5, 7, 9)
            and all(ch in "0123456789abcdefABCDEF" for ch in c[1:]))


# Marca blanca: si se define un acento válido, se redefine el token en TODAS las páginas.
# !important gana sobre las definiciones de styles.css (claro, oscuro y automático), sin tocarlo.
if ACCENT and _valid_hex(ACCENT):
    _ACCENT_STYLE = (
        "<style>:root{"
        f"--accent:{ACCENT}!important;--accent-strong:{ACCENT}!important;"
        f"--accent-weak:color-mix(in srgb,{ACCENT} 12%,transparent)!important;"
        "--accent-contrast:#fff!important;"
        f"--accent-grad:linear-gradient(135deg,{ACCENT},{ACCENT})!important;"
        f"--accent-line:linear-gradient(90deg,{ACCENT},{ACCENT})!important;"
        "}</style>")
else:
    _ACCENT_STYLE = ""


# ── PWA: instalable como app (manifest + service worker + iconos) ─────────────────────────────
# Permite "Instalar app" en móvil y escritorio → icono propio y ventana sin barra, sin teclear
# IP:puerto. Los iconos son ficheros en web/ (icon-192.png / icon-512.png); manifest y SW se
# sirven como rutas públicas en do_GET.
PWA_MANIFEST = json.dumps({
    "name": BRAND_NAME,
    "short_name": BRAND_NAME[:12],
    "description": "Transferencia de archivos self-hosted, en tu red local.",
    "start_url": "/",
    "scope": "/",
    "display": "standalone",
    "background_color": "#0b1120",
    "theme_color": "#0b1120",
    "icons": [
        {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
        {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any"},
    ],
}, ensure_ascii=False).encode("utf-8")

# Service worker MÍNIMO y SEGURO: solo cachea los 3 estáticos de la PWA (para poder instalarse y
# abrir). Todo lo demás —páginas con login, API, descargas, subidas— va SIEMPRE a la red: nunca
# se guarda contenido privado en la caché del navegador.
PWA_SW_JS = (
    "const C='hylanlock-pwa-v1';"
    "const A=['/icon-192.png','/icon-512.png','/manifest.webmanifest'];"
    "self.addEventListener('install',e=>{e.waitUntil(caches.open(C).then(c=>c.addAll(A)).catch(()=>{}));self.skipWaiting();});"
    "self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==C).map(x=>caches.delete(x)))));self.clients.claim();});"
    "self.addEventListener('fetch',e=>{if(e.request.method!=='GET')return;"
    "const u=new URL(e.request.url);if(A.includes(u.pathname)){e.respondWith(caches.match(e.request).then(r=>r||fetch(e.request)));}});"
).encode("utf-8")

# Etiquetas que se inyectan en el <head> y antes de </body> de TODAS las páginas (ver _inject_theme).
_PWA_HEAD = (
    '<link rel="manifest" href="/manifest.webmanifest">'
    '<link rel="icon" href="/icon-192.png">'
    '<link rel="apple-touch-icon" href="/icon-192.png">'
    '<meta name="mobile-web-app-capable" content="yes">'
    '<meta name="apple-mobile-web-app-capable" content="yes">'
    '<meta name="apple-mobile-web-app-title" content="' + html.escape(BRAND_NAME) + '">'
)
_PWA_SW = ('<script>if("serviceWorker" in navigator){window.addEventListener("load",'
           'function(){navigator.serviceWorker.register("/sw.js").catch(function(){});});}</script>')


def _inject_theme(text):
    """Añade el script de tema y el acento de marca en <head>, el SW antes de </body>, y aplica el
    nombre/logo de marca (__BRAND__/__LOGO__) en TODAS las páginas. La marca (nombre, logo, acento)
    se lee de la BD (Ajustes) con respaldo al entorno, así se puede configurar en caliente."""
    bname, blogo, bacc = brand_name(), brand_logo(), brand_accent()
    # Acento de marca: si hay un color válido, redefine el token en todas las páginas (!important).
    accent_style = ""
    if bacc and _valid_hex(bacc):
        accent_style = (
            "<style>:root{"
            f"--accent:{bacc}!important;--accent-strong:{bacc}!important;"
            f"--accent-weak:color-mix(in srgb,{bacc} 12%,transparent)!important;"
            "--accent-contrast:#fff!important;"
            f"--accent-grad:linear-gradient(135deg,{bacc},{bacc})!important;"
            f"--accent-line:linear-gradient(90deg,{bacc},{bacc})!important;"
            "}</style>")
    text = text.replace("<head>", "<head>" + _THEME_HEAD + accent_style + _PWA_HEAD, 1)
    # El tema se elige ahora en Ajustes (no un botón flotante). _THEME_HEAD sigue aplicando la
    # preferencia guardada (o la del sistema) en cada página, incluidas login y los enlaces de buzón.
    text = text.replace("</body>", _PWA_SW + "</body>", 1)
    text = text.replace("__BRAND__", html.escape(bname)).replace("__LOGO__", html.escape(blogo) if blogo else BRAND_LOGO_SVG)
    if bname != "Hylanlock":
        # Rebrand del nombre en textos que aún digan "Hylanlock" (seguro: las clases/ids usan "hyl-").
        text = text.replace("Hylanlock", html.escape(bname))
    return text


# Script que reparte el token CSRF automáticamente: lo añade como campo oculto a cualquier
# formulario POST al enviarse, y como cabecera X-CSRF a los fetch/XHR POST. Así ninguna página
# tiene que ocuparse del token a mano.
_CSRF_JS = (
    '<script>(function(){'
    'var m=document.querySelector("meta[name=hyl-csrf]"),T=m?m.content:"";window.HYL_CSRF=T;'
    'document.addEventListener("submit",function(e){var f=e.target;'
    'if(f&&(f.method||"").toLowerCase()==="post"&&!f.querySelector(\'input[name=__csrf__]\')){'
    'var i=document.createElement("input");i.type="hidden";i.name="__csrf__";i.value=T;f.appendChild(i);}},true);'
    'var of=window.fetch;if(of)window.fetch=function(u,o){o=o||{};'
    'if((o.method||"GET").toUpperCase()==="POST"){o.headers=new Headers(o.headers||{});o.headers.set("X-CSRF",T);}'
    'return of(u,o);};'
    'var oo=XMLHttpRequest.prototype.open,os=XMLHttpRequest.prototype.send;'
    'XMLHttpRequest.prototype.open=function(mm){this.__csrfm=mm;return oo.apply(this,arguments);};'
    'XMLHttpRequest.prototype.send=function(){if((this.__csrfm||"").toUpperCase()==="POST"){'
    'try{this.setRequestHeader("X-CSRF",T);}catch(e){}}return os.apply(this,arguments);};'
    '})();</script>'
)


def _inject_csrf(text_bytes, token):
    """Inyecta el token CSRF (meta en <head> + script) en una página HTML ya autenticada."""
    try:
        s = text_bytes.decode("utf-8")
    except Exception:
        return text_bytes
    if "</body>" not in s:
        return text_bytes
    s = s.replace("<head>", '<head><meta name="hyl-csrf" content="' + token + '">', 1)
    s = s.replace("</body>", _CSRF_JS + "</body>", 1)
    return s.encode("utf-8")


def render(page, url="", qr_svg="", err="", pwpill="", depts="", slug="", depname="", nxt=""):
    return _inject_theme(
        _template(page).replace("__CSS__", _template(CSS))
                .replace("__URL__", url)
                .replace("__QR__", qr_svg)
                .replace("__ERR__", err)
                .replace("__PWPILL__", pwpill)
                .replace("__DEPTS__", depts)
                .replace("__SLUG__", slug)
                .replace("__DEPNAME__", html.escape(depname))
                .replace("__NEXT__", html.escape(nxt))
    ).encode("utf-8")


_STEPUP_CODE_FIELD = ('<input type="text" name="code" placeholder="Código de 6 cifras de tu app" required '
                      'inputmode="numeric" autocomplete="one-time-code" maxlength="20">')


def render_stepup(nxt, err="", need_code=False):
    """Pantalla de step-up. Con 2FA activado pide también el código: si no, una contraseña robada
    bastaría para elevar una sesión robada."""
    return render(STEPUP_PAGE, err=err, nxt=nxt).replace(
        b"__CODEFIELD__", _STEPUP_CODE_FIELD.encode("utf-8") if need_code else b"")


def render_twofa(err=""):
    """Pantalla del segundo paso del login (código TOTP o de recuperación)."""
    return _inject_theme(_template(TWOFA_PAGE).replace("__CSS__", _template(CSS))
                         .replace("__ERR__", err)).encode("utf-8")


def render_activate(username="", token="", err="", formcls=""):
    """Pantalla pública de activación (poner contraseña con un token de invitación)."""
    return _inject_theme(
        _template(ACTIVATE_PAGE).replace("__CSS__", _template(CSS))
                .replace("__USERNAME__", html.escape(username))
                .replace("__TOKEN__", html.escape(token))
                .replace("__ERR__", err)
                .replace("__MINLEN__", str(MIN_PASSWORD))
                .replace("__FORMCLS__", formcls)).encode("utf-8")


def render_buzon_drop(ok=True, token="", label="", err=""):
    """Pantalla PÚBLICA del enlace de buzón: solo zona de soltar. Si el enlace no vale, se oculta
    el formulario y se muestra el error."""
    etiqueta = html.escape(label) if label else "Deja aquí tus archivos de forma privada"
    if not ok:
        err = ('<div class="err-msg">Este enlace no es válido o se ha revocado. '
               'Pide uno nuevo a quien te lo compartió.</div>')
        etiqueta = "Enlace no disponible"
    return _inject_theme(
        _template(BUZON_PAGE).replace("__CSS__", _template(CSS))
                .replace("__TOKEN__", html.escape(token))
                .replace("__LABEL__", etiqueta)
                .replace("__ERR__", err)
                .replace("__FORMCLS__", "" if ok else "hide")).encode("utf-8")


def render_setup(err=""):
    """Asistente de primer arranque: crear el administrador e instalar la licencia."""
    return _inject_theme(
        _template(SETUP_PAGE).replace("__CSS__", _template(CSS))
                .replace("__ERR__", err)
                .replace("__MINLEN__", str(MIN_PASSWORD))).encode("utf-8")


def render_blocked(title, msg, detail, actions):
    """Pantalla de bloqueo por licencia (msg y actions llevan HTML; title/detail se escapan)."""
    return _inject_theme(
        _template(BLOCKED_PAGE).replace("__CSS__", _template(CSS))
                .replace("__TITLE__", html.escape(title))
                .replace("__MSG__", msg)
                .replace("__DETAIL__", html.escape(detail))
                .replace("__ACTIONS__", actions)).encode("utf-8")


_LIC_LABELS = {license.VALID: "Activa", license.EXPIRED: "Caducada",
               license.INVALID: "No válida", license.MISSING: "Sin licencia"}


def render_license(state, err="", ok=""):
    """Pantalla de admin con el estado de la licencia y el formulario para instalar una nueva."""
    st = state["status"]
    days = state.get("days_left")
    days_txt = "—"
    if st == license.VALID and days is not None:
        days_txt = f"{days} día(s) restantes"
    elif st == license.EXPIRED and days is not None:
        days_txt = f"caducó hace {abs(days)} día(s)"
    return _inject_theme(
        _template(LICENSE_PAGE).replace("__CSS__", _template(CSS))
                .replace("__STATUS__", html.escape(_LIC_LABELS.get(st, st)))
                .replace("__STATUS_CLS__", "ok" if st == license.VALID else "err")
                .replace("__CUSTOMER__", html.escape(str(state.get("customer") or "—")))
                .replace("__TYPE__", html.escape(str(state.get("type") or "—")))
                .replace("__EXPIRES__", html.escape(str(state.get("expires") or "—")))
                .replace("__DAYS__", html.escape(days_txt))
                .replace("__ERR__", err)
                .replace("__OK__", ok)).encode("utf-8")


_EV_ICONS = {"login_ok": "", "login_fail": "", "logout": "", "logout_all": "",
             "upload": "", "upload_dep": "", "upload_sub": "", "download": "", "sync_pull": "",
             "brute_block": "", "stepup_ok": "", "stepup_fail": "",
             "user_create": "", "user_delete": "", "user_rename": "",
             "user_pwreset": "", "user_role": "", "dep_create": "", "dep_delete": "",
             "invite_create": "", "account_activated": "",
             "license_install": "", "data_export": "",
             "access_request": "", "access_approved": "", "access_rejected": "",
             "setup_done": "", "login_ldap": "", "news_seen": ""}


LOG_LIMITES = (100, 200, 500, 1000)


def _opciones(valores, elegido, vacio):
    """Opciones de un <select>, marcando la elegida. Todo escapado: los valores salen de la BD."""
    fuera = [f'<option value="">{html.escape(vacio)}</option>']
    for v in valores:
        sel = " selected" if v == elegido else ""
        fuera.append(f'<option value="{html.escape(v)}"{sel}>{html.escape(v)}</option>')
    return "".join(fuera)


def log_markers(query=None):
    """Devuelve (resumen, filas, formulario de filtros) del registro, para el shell.

    Los filtros se aplican EN LA BASE DE DATOS, no en el navegador: filtrar en el cliente exigiría
    traerse la auditoría entera a la página, que es justo lo que no se puede hacer cuando tiene
    cientos de miles de eventos.
    """
    query = query or {}
    def uno(clave):
        return (query.get(clave, [""])[0] or "").strip()

    # Los campos datetime-local del navegador mandan 'AAAA-MM-DDTHH:MM' con una T en medio;
    # en la BD la marca de tiempo lleva un espacio. Se normaliza aquí, en la frontera.
    desde, hasta = uno("desde").replace("T", " "), uno("hasta").replace("T", " ")
    tipo, usuario, texto = uno("tipo"), uno("usuario"), uno("q")
    try:
        limite = int(uno("limite") or 200)
    except ValueError:
        limite = 200
    if limite not in LOG_LIMITES:
        limite = 200

    events = db.search_events(limit=limite, desde=desde or None, hasta=hasta or None,
                              tipo=tipo or None, usuario=usuario or None, texto=texto or None)
    rows = []
    for e in events:
        ic = _EV_ICONS.get(e["type"], "•")
        size = human_size(e["bytes"]) if e["bytes"] else ""
        quien = e["user"] or "—"
        rows.append(
            f"<tr><td>{html.escape(e['ts'])}</td>"
            f"<td>{ic} {html.escape(e['type'])}</td>"
            f"<td>{html.escape(quien)}</td>"
            f"<td>{html.escape(e['origin'] or '')}</td>"
            f"<td class='detail'>{html.escape(e['detail'] or '')}</td>"
            f"<td>{size}</td></tr>")

    filtrando = any((desde, hasta, tipo, usuario, texto))
    if rows:
        body = "\n".join(rows)
    elif filtrando:
        body = ('<tr><td colspan="6" class="empty">Ningún evento cumple esos filtros. '
                'Prueba a ampliar el tramo de fechas.</td></tr>')
    else:
        body = '<tr><td colspan="6" class="empty">Sin eventos aún…</td></tr>'

    # Resumen: si hay filtros, cuenta lo encontrado; si no, el reparto por tipo de siempre.
    if filtrando:
        tope = " (tope de la página)" if len(events) >= limite else ""
        summary = html.escape(f"{len(events)} evento(s) encontrados{tope}")
    else:
        summary = html.escape(" · ".join(f"{k}: {v}" for k, v in db.stats().items()) or "Sin datos")

    opciones_limite = "".join(
        f'<option value="{n}"{" selected" if n == limite else ""}>{n}</option>'
        for n in LOG_LIMITES)

    formulario = f'''<form class="filtros" method="get" action="/log">
  <label>Desde<input type="datetime-local" name="desde"
         value="{html.escape(desde.replace(" ", "T")[:16])}"></label>
  <label>Hasta<input type="datetime-local" name="hasta"
         value="{html.escape(hasta.replace(" ", "T")[:16])}"></label>
  <label>Evento<select name="tipo">{_opciones(db.event_types(), tipo, "Todos")}</select></label>
  <label>Usuario<select name="usuario">{_opciones(db.event_users(), usuario, "Todos")}</select></label>
  <label class="ancho">Buscar<input type="search" name="q" value="{html.escape(texto)}"
         placeholder="archivo, mensaje o IP"></label>
  <label>Mostrar<select name="limite">{opciones_limite}</select></label>
  <div class="acciones">
    <button type="submit" class="btn">Filtrar</button>
    <a class="btn2" href="/log">Limpiar</a>
    <a class="btn2" href="{html.escape(_log_export_href(desde, hasta, tipo, usuario, texto))}">Exportar CSV</a>
  </div>
</form>'''
    return summary, body, formulario


# Tope de filas por exportación: un auditor quiere el conjunto filtrado entero, pero sin permitir
# construir en memoria un CSV ilimitado de una auditoría de años. Se acota y se avisa en el nombre.
CSV_MAX = 100000


def _log_export_href(desde, hasta, tipo, usuario, texto):
    """Enlace a /log.csv que arrastra los MISMOS filtros que la pantalla."""
    params = {k: v for k, v in (("desde", desde), ("hasta", hasta), ("tipo", tipo),
                                ("usuario", usuario), ("q", texto)) if v}
    qs = urllib.parse.urlencode(params)
    return "/log.csv" + ("?" + qs if qs else "")


def _csv_safe(v):
    """Anti-inyección de fórmulas (CSV injection): una celda que empieza por = + - @ (o por tabulador
    o retorno de carro) la interpreta la hoja de cálculo como fórmula. Se antepone un apóstrofo, que
    Excel/Sheets tratan como texto literal."""
    s = "" if v is None else str(v)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        s = "'" + s
    return s


def build_log_csv(query):
    """Construye el CSV del registro con los MISMOS filtros que /log (aplicados en la BD).
    Devuelve (bytes UTF-8 con BOM para que Excel abra bien los acentos, nº de filas)."""
    query = query or {}
    def uno(clave):
        return (query.get(clave, [""])[0] or "").strip()
    desde, hasta = uno("desde").replace("T", " "), uno("hasta").replace("T", " ")
    tipo, usuario, texto = uno("tipo"), uno("usuario"), uno("q")
    events = db.search_events(limit=CSV_MAX, desde=desde or None, hasta=hasta or None,
                              tipo=tipo or None, usuario=usuario or None, texto=texto or None)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["fecha_hora", "evento", "usuario", "origen", "ip", "detalle", "bytes"])
    for e in events:
        w.writerow([_csv_safe(e["ts"]), _csv_safe(e["type"]), _csv_safe(e["user"]),
                    _csv_safe(e["origin"]), _csv_safe(e["ip"]), _csv_safe(e["detail"]),
                    e["bytes"] if e["bytes"] else ""])
    return ("﻿" + buf.getvalue()).encode("utf-8"), len(events)


# ============================================================ POLÍTICA DE RUTAS (Paso 0.5)
# Fuente ÚNICA de qué exige cada ruta. El dispatcher (_enforce) la aplica ANTES de llamar al
# handler, así la autorización no se puede "olvidar" en un endpoint. Campos del guard:
#   lan=True           -> requiere estar en la LAN
#   perm="x.y"         -> requiere el permiso RBAC (opcionalmente sobre un departamento)
#   deny_redirect="/x" -> al denegar por permiso, redirige ahí (302) en vez de 403
# Ausencia de 'perm' = basta con estar autenticado. Rutas públicas (login/logout/iconos) se
# gestionan aparte, antes del dispatcher.
_GUARD_GET = {
    "/":                       {},   # home = bienvenida (solo autenticado)
    "/index.html":             {},
    "/departamentos":          {"lan": True},
    "/api/departamentos":      {"lan": True},
    "/api/subcarpetas":        {"lan": True},   # el handler filtra por permiso cada subcarpeta
    "/api/v1/sync/manifest":   {"lan": True},   # agente de sincronización (solo LAN, por decisión)
    # --- API pública v1 (SOLO LECTURA). El permiso se comprueba por carpeta en cada handler.
    "/api/v1/openapi.json":    {"lan": True},   # descubrimiento del contrato, misma protección
    "/api/v1/whoami":          {"lan": True},
    "/api/v1/folders":         {"lan": True},
    "/api/v1/files":           {"lan": True},
    "/api/v1/download":        {"lan": True},
    "/api/perfil/tokens":      {"lan": True},
    "/api/novedades":          {"lan": True},   # avisos de archivos nuevos (derivados de auditoría)
    "/elevate":                {},   # step-up: solo autenticado
    "/admin":                  {"lan": True, "perm": "users.manage", "elevated": True},
    "/api/admin/users":        {"lan": True, "perm": "users.manage", "elevated": True},
    "/api/admin/departments":  {"lan": True, "perm": "depts.manage", "elevated": True},
    "/api/admin/subfolders":   {"lan": True, "perm": "depts.manage", "elevated": True},
    "/api/admin/services":     {"lan": True, "perm": "users.manage", "elevated": True},
    "/api/admin/config":       {"lan": True, "perm": "users.manage", "elevated": True},
    "/admin/licencia":         {"lan": True, "perm": "users.manage"},
    "/admin/export":           {"lan": True, "perm": "users.manage"},
    "/api/admin/license":      {"lan": True, "perm": "users.manage"},
    "/perfil":                 {"lan": True},
    "/api/perfil":             {"lan": True},
    "/api/admin/requests":     {"lan": True, "perm": "depts.manage", "elevated": True},
    "/log":                    {"perm": "audit.view"},
    "/log.csv":                {"perm": "audit.view"},
    "/api/log":                {"perm": "audit.view"},
    "/upload/status":          {},   # solo autenticado
    "/ajustes":                {},   # Ajustes: autenticado (el bloque de admin se decide dentro)
    "/gobernanza":             {"lan": True, "perm": "folder.oversee"},   # ver estructura SIN leer
    "/papelera":               {"lan": True, "perm": "users.manage"},     # papelera: solo admins
}
_GUARD_POST = {
    "/upload/chunk":           {},
    "/upload/complete":        {},   # el handler comprueba depto/admin por dentro
    "/logout-all":             {},
    "/elevate":                {},   # step-up (re-auth). CSRF aplica igual.
    "/admin/users/add":        {"lan": True, "perm": "users.manage", "elevated": True},
    "/admin/users/del":        {"lan": True, "perm": "users.manage", "elevated": True},
    "/admin/dep/add":          {"lan": True, "perm": "depts.manage", "elevated": True},
    "/admin/dep/del":          {"lan": True, "perm": "depts.manage", "elevated": True},
    "/admin/dep/assign":       {"lan": True, "perm": "depts.manage", "elevated": True},
    "/admin/dep/unassign":     {"lan": True, "perm": "depts.manage", "elevated": True},
    "/admin/user/boss":        {"lan": True, "perm": "users.manage", "elevated": True},
    "/admin/user/rename":      {"lan": True, "perm": "users.manage", "elevated": True},
    "/admin/user/password":    {"lan": True, "perm": "users.manage", "elevated": True},
    "/admin/user/role":        {"lan": True, "perm": "users.manage", "elevated": True},
    "/admin/invite":           {"lan": True, "perm": "users.manage", "elevated": True},
    "/admin/config/extensiones": {"lan": True, "perm": "users.manage", "elevated": True},
    "/admin/config/marca":      {"lan": True, "perm": "users.manage", "elevated": True},
    "/admin/exposicion/revisado": {"lan": True, "perm": "users.manage"},   # solo oculta el aviso
    "/admin/user/supervisor":  {"lan": True, "perm": "users.manage", "elevated": True},
    # Papelera (solo admins): borrar y restaurar se pueden deshacer; eliminar de verdad, no -> step-up.
    "/admin/papelera/borrar":    {"lan": True, "perm": "users.manage"},
    "/admin/papelera/restaurar": {"lan": True, "perm": "users.manage"},
    "/admin/papelera/eliminar":  {"lan": True, "perm": "users.manage", "elevated": True},
    "/admin/config/papelera":    {"lan": True, "perm": "users.manage", "elevated": True},
    "/admin/licencia":         {"lan": True, "perm": "users.manage"},
    "/perfil/solicitar":       {"lan": True},
    # Despachar avisos sin abrir la carpeta. No hace falta step-up: no concede acceso ni borra
    # nada, solo mueve TU marca de "visto hasta aquí".
    "/novedades/leidas":       {"lan": True},
    # Tokens de dispositivo: el usuario gestiona los suyos. Step-up porque crear una credencial
    # de larga duración es una acción sensible.
    "/perfil/token/new":       {"lan": True, "elevated": True},
    # 2FA: activarlo es para administradores; desactivarlo o renovar códigos, para quien lo tenga.
    "/perfil/2fa/iniciar":     {"lan": True, "perm": "users.manage", "elevated": True},
    "/perfil/2fa/activar":     {"lan": True, "perm": "users.manage", "elevated": True},
    "/perfil/2fa/desactivar":  {"lan": True, "elevated": True},
    "/perfil/2fa/codigos":     {"lan": True, "elevated": True},
    "/admin/user/2fa/reset":   {"lan": True, "perm": "users.manage", "elevated": True},
    "/admin/config/2fa":       {"lan": True, "perm": "users.manage", "elevated": True},
    "/perfil/token/revoke":    {"lan": True},
    "/admin/request/resolve":  {"lan": True, "perm": "depts.manage", "elevated": True},
    # Subcarpetas y su ACL: misma protección que gestionar departamentos.
    "/admin/sub/add":          {"lan": True, "perm": "depts.manage", "elevated": True},
    "/admin/sub/del":          {"lan": True, "perm": "depts.manage", "elevated": True},
    "/admin/sub/link":         {"lan": True, "perm": "depts.manage", "elevated": True},
    "/admin/sub/link/revoke":  {"lan": True, "perm": "depts.manage", "elevated": True},
    "/admin/sub/access":       {"lan": True, "perm": "depts.manage", "elevated": True},
    # Cuentas de servicio (integraciones). Crear una credencial de máquina de larga vida es de lo
    # más sensible del panel: users.manage + step-up.
    "/admin/service/add":      {"lan": True, "perm": "users.manage", "elevated": True},
    "/admin/service/del":      {"lan": True, "perm": "users.manage", "elevated": True},
    "/admin/service/key":      {"lan": True, "perm": "users.manage", "elevated": True},
    "/admin/service/revoke":   {"lan": True, "perm": "users.manage", "elevated": True},
    "/admin/service/remote":   {"lan": True, "perm": "users.manage", "elevated": True},
    # API pública v2: subida en UNA petición. El permiso ('files.upload' sobre la carpeta) se
    # comprueba dentro, porque la carpeta viene en la query.
    "/api/v1/upload":          {"lan": True},
}
# Rutas de departamento (dinámicas): LAN + el permiso RBAC que corresponda A ESA ACCIÓN sobre
# ese depto. Antes las tres pasaban por 'dept.view' (todo-o-nada); ahora cada una exige lo suyo,
# que es lo que permite conceder subida SIN descarga (buzón de entrega).
_DEP_GUARD = {"lan": True, "perm": "dept.view"}            # abrir la página del departamento
_DEP_GUARD_LIST = {"lan": True, "perm": "files.list"}      # ver el listado de archivos
_DEP_GUARD_DOWNLOAD = {"lan": True, "perm": "files.download"}   # descargar un archivo

# Rutas que el ADMIN conserva aunque la licencia NO sea válida: ver estado, subir una nueva y
# EXPORTAR sus datos. Todo lo demás se bloquea (uso), pero los datos jamás se tocan.
# --------------------------------------------------------------- API pública (/api/v1)
# Frontera IMPORTANTE: /api/v1/* es el CONTRATO PÚBLICO (estable, versionado). El resto de /api/*
# es el backend interno de las pantallas y puede cambiar sin aviso al rediseñar la interfaz.
API_PREFIX = "/api/v1/"
# Peticiones por minuto y por clave. Protege de una integración con un bucle mal escrito, que es
# el caso realista mucho antes que un atacante.
API_RATE_LIMIT = int(os.environ.get("HYLANLOCK_API_RATE", "120"))
# Tope por petición en la subida por API (la web sigue subiendo por trozos, sin este límite).
API_MAX_UPLOAD = int(os.environ.get("HYLANLOCK_API_MAX_UPLOAD_MB", "512")) * 1024 * 1024
_api_hits = {}                       # huella de la clave -> [instantes de las últimas peticiones]
_api_hits_lock = threading.Lock()


def api_rate_ok(huella):
    """Ventana deslizante de 60 s por clave. Devuelve (permitido, peticiones_en_la_ventana)."""
    ahora = time.time()
    with _api_hits_lock:
        hits = [t for t in _api_hits.get(huella, []) if ahora - t < 60]
        permitido = len(hits) < API_RATE_LIMIT
        if permitido:
            hits.append(ahora)
        _api_hits[huella] = hits
        if len(_api_hits) > 500:     # no crecer sin límite si rotan muchas claves
            for k in [k for k, v in _api_hits.items() if not v or ahora - v[-1] > 300]:
                _api_hits.pop(k, None)
    return permitido, len(hits)


# Límite de ENTREGAS por enlace de buzón (subida anónima): por IP y ventana de 60 s. Acota el abuso
# de una subida sin login. Se mide en 'complete' (archivo terminado), no en cada trozo, para no
# romper archivos grandes (muchos trozos). Por defecto 20 archivos/min por IP.
BUZON_RATE = int(_env("BUZON_RATE", "20"))
_buzon_hits = {}
_buzon_hits_lock = threading.Lock()


def buzon_rate_ok(ip):
    """Ventana deslizante de 60 s por IP para las entregas de buzón. Devuelve (permitido, nº)."""
    ahora = time.time()
    with _buzon_hits_lock:
        hits = [t for t in _buzon_hits.get(ip, []) if ahora - t < 60]
        permitido = len(hits) < BUZON_RATE
        if permitido:
            hits.append(ahora)
        _buzon_hits[ip] = hits
        if len(_buzon_hits) > 500:
            for k in [k for k, v in _buzon_hits.items() if not v or ahora - v[-1] > 300]:
                _buzon_hits.pop(k, None)
    return permitido, len(hits)


LICENSE_BYPASS_ADMIN = {"/admin/licencia", "/admin/export", "/api/admin/license"}


def license_refresh(server, force=False):
    """Devuelve el estado de licencia cacheado en el server; lo recalcula (verificación Ed25519, cara)
    solo al arrancar, cada hora, o si cambia el archivo license.key. Persiste el high-water mark."""
    now = time.time()
    path = os.path.join(DATA_DIR, license.LICENSE_FILENAME)
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = None
    cur = getattr(server, "license_cache", None)
    if (not force and cur and (now - cur["checked"] < 3600) and cur["mtime"] == mtime):
        return cur["result"]
    text = license.read_license_file(DATA_DIR)
    seen = db.meta_get("license_seen")
    res = license.evaluate(text, seen_iso=seen)
    if res["new_seen"] and res["new_seen"] != seen:
        db.meta_set("license_seen", res["new_seen"])   # anti-rollback: la fecha vista nunca retrocede
    server.license_cache = {"result": res, "checked": now, "mtime": mtime}
    return res


class Handler(BaseHTTPRequestHandler):
    # Cabecera 'Server' neutra: no filtrar un nombre en clave (antes "PasarRoms", heredado del buzón
    # personal) ni la versión de Python. Neutro también ayuda a la marca blanca.
    server_version = "web"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    # -------------------------------------------------- helpers
    def _send(self, code, body=b"", ctype="text/html; charset=utf-8", extra=None):
        # En páginas HTML de un usuario autenticado, inyecta el token CSRF (meta + script).
        if code == 200 and body and ctype.startswith("text/html"):
            u = self._current_user()
            if u:
                tv = (db.get_user(u[0]) or {}).get("token_version", 1)
                body = _inject_csrf(body, csrf_token(self.server.session_token, u[0], tv))
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # Cabeceras de seguridad (A3). La app es autocontenida (sin CDNs), así que default-src 'self'
        # no rompe nada; se permite 'unsafe-inline' porque el CSS y algún script (p. ej. el inyector
        # del token CSRF) van en línea. 'frame-ancestors none' y X-Frame-Options: DENY = anti-clickjacking.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; img-src 'self' data:; "
                         "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
                         "object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        if self._tls():          # solo si se sirve por HTTPS (perfil Caddy): fuerza TLS un año.
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        if extra:
            for k, v in extra:
                self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _invite_url(self, token):
        """URL absoluta de activación, usando el Host con el que llegó la petición (accesible al cliente)."""
        host = self.headers.get("Host") or f"127.0.0.1:{PORT}"
        return f"http://{host}/activar?token={token}"

    def _buzon_url(self, token):
        """URL absoluta de un enlace de buzón, con el Host de la petición. Respeta HTTPS si se sirve
        cifrado, para que el enlace compartido funcione igual."""
        host = self.headers.get("Host") or f"127.0.0.1:{PORT}"
        scheme = "https" if self._tls() else "http"
        return f"{scheme}://{host}/b/{token}"

    def _qr_svg(self, url):
        try:
            return qr.to_svg(qr.encode(url), quiet=2, module=6)
        except Exception:
            return ""

    def _client_ip(self):
        # Por defecto = IP real del socket TCP (no se confía en cabeceras). SOLO si hay proxies de
        # confianza configurados (HYLANLOCK_TRUSTED_PROXIES) y la conexión viene de uno, se usa
        # X-Forwarded-For para recuperar la IP del cliente. Un cliente cualquiera NO puede falsear
        # su IP mandando la cabecera, porque el XFF solo se lee viniendo de un proxy de confianza.
        return real_client_ip(self.client_address[0], self.headers.get("X-Forwarded-For", ""))

    def _tls(self):
        """¿La petición llega por HTTPS? Sirve para marcar la cookie 'Secure' y emitir HSTS.
        Se cree por 'X-Forwarded-Proto: https' SOLO si el peer es un proxy de confianza (mismo
        criterio anti-spoofing que la IP real); o por la pista explícita HYLANLOCK_BEHIND_TLS."""
        if BEHIND_TLS or TLS_ON:
            return True
        peer = self.client_address[0] if self.client_address else ""
        if _TRUSTED_PROXY_NETS and _ip_in(peer, _TRUSTED_PROXY_NETS):
            return self.headers.get("X-Forwarded-Proto", "").strip().lower() == "https"
        return False

    def _origin(self):
        # LAN configurada = local; cualquier otra (proxy = 127.0.0.1) = remoto.
        return "local" if ip_es_lan(self._client_ip()) else "remoto"

    def _is_lan(self):
        # Candado de zonas locales: SOLO IP real de la LAN configurada (proxy=127.0.0.1 -> False).
        return ip_es_lan(self._client_ip())

    def _api_error(self, code, detail, status):
        """Error uniforme de la API pública: {"error": "codigo", "detail": "…"} + HTTP correcto.
        Un formato único hace que integrar sea predecible."""
        self._send(status, json.dumps({"error": code, "detail": detail}).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _api_folder(self, clave):
        """Traduce la clave de carpeta de la API ('ventas' o 'ventas/ana-privado') en
        (dep, sub, carpeta_en_disco), comprobando ANTES el permiso 'perm' que se pida aparte.
        Devuelve (None, None, None) si la clave no tiene forma válida."""
        clave = (clave or "").strip().strip("/")
        if not clave or clave.count("/") > 1:
            return None, None, None
        dep, _, sub = clave.partition("/")
        dep = os.path.basename(dep)
        sub = os.path.basename(sub) if sub else None
        if not dep or (sub is not None and not sub):
            return None, None, None
        return dep, sub, (sub_dir(dep, sub) if sub else dep_dir(dep))

    def _bearer_user(self):
        """Devuelve (usuario, scope) si la petición trae un token de dispositivo válido.

        Es la credencial del AGENTE de sincronización (software desatendido). No amplía permisos:
        actúa exactamente como su dueño. Ojo: una sesión por token NUNCA está 'elevada', así que
        no puede hacer acciones con step-up; y como no sabe el secreto de sesión, no puede formar
        un token CSRF válido -> los POST con Bearer fallan cerrado. Para sincronizar (solo GET)
        es justo lo que hace falta."""
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        return db.verify_device_token(auth[7:].strip())

    def _cookie_value(self, name):
        for part in self.headers.get("Cookie", "").split(";"):
            part = part.strip()
            if part.startswith(name + "="):
                return part[len(name) + 1:]
        return ""

    def _finish_login(self, username, scope, remember, ip, detail=None, clear_2fa=False):
        """Emite la sesión y entra (tras la contraseña, y tras el código si hay 2FA)."""
        clear_login_fails(ip)
        db.log_event("login_ok", user=username, origin=self._origin(), ip=ip, detail=detail)
        tv = (db.get_user(username) or {}).get("token_version", 1)
        elev = int(time.time()) + STEPUP_MINUTES * 60   # login = elevación inicial
        value = make_session(self.server.session_token, username, scope, tv, elev, 1 if remember else 0)
        extra = [("Location", "/"), ("Set-Cookie", session_cookie(value, remember, secure=self._tls()))]
        if clear_2fa:
            extra.append(("Set-Cookie", twofa_cookie("", self._tls())))
        # Todos aterrizan en la home de bienvenida (guía rápida). Desde ahí, a departamentos.
        self._send(302, extra=extra)
        if self._origin() == "remoto":
            notify_telegram(f"Acceso remoto desde Internet\n"
                            f"Usuario: {username}\nHora: {time.strftime('%H:%M')}")

    def _cookie_user(self):
        """(usuario, scope) de una sesión de COOKIE válida y vigente, o None. Solo cookie.
        Además de la firma HMAC, valida contra la BD: el usuario existe, está ACTIVO y su
        token_version coincide con la cookie. Así, desactivar un usuario o subir su token_version
        (p. ej. "cerrar en todos los dispositivos") invalida sus sesiones al instante."""
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("pr_token="):
                parsed = parse_session(self.server.session_token, part[9:])
                if not parsed:
                    return None
                username, scope, tv, _elev, _rem = parsed
                u = db.get_user(username)
                if not u or u["status"] != "active" or u["token_version"] != tv:
                    return None
                return (username, scope)
        return None

    def _current_user(self):
        """Quién hace la petición: primero la cookie (personas), y si no hay, el token (máquinas)."""
        return self._cookie_user() or self._bearer_user()

    def _solo_bearer(self):
        """True si la petición se autentica ÚNICAMENTE con un token de dispositivo.

        Esta es LA comprobación delicada de la API de escritura. El CSRF existe para proteger
        credenciales AMBIENTALES (la cookie, que el navegador envía sola). Un token no es
        ambiental: se pone a mano, así que un sitio malicioso no puede provocarlo. Por eso se puede
        eximir del CSRF a una petición con token.
        PERO la regla tiene que ser "NO hay cookie válida Y el token resuelve", nunca "trae la
        cabecera Authorization": si fuera lo segundo, una petición con la cookie de la víctima MÁS
        una cabecera Bearer cualquiera se saltaría el CSRF. Ese es el error clásico."""
        return self._cookie_user() is None and self._bearer_user() is not None

    def _session_field(self, idx):
        """Devuelve un campo del token de sesión (idx sobre la tupla de parse_session), o 0."""
        for part in self.headers.get("Cookie", "").split(";"):
            part = part.strip()
            if part.startswith("pr_token="):
                parsed = parse_session(self.server.session_token, part[9:])
                return parsed[idx] if parsed else 0
        return 0

    def _is_elevated(self):
        """True si la sesión está 'elevada' (re-autenticada hace poco, step-up vigente)."""
        return self._session_field(3) > int(time.time())   # idx 3 = elev_exp

    def _authed(self):
        return self._current_user() is not None

    def _has(self, perm, dept=None, sub=None):
        """¿El usuario logueado tiene el permiso RBAC 'perm' (opcionalmente sobre 'dept', y dentro
        de él sobre la subcarpeta 'sub')? Único punto por el que pasa la autorización."""
        u = self._current_user()
        return bool(u) and db.has_permission(u[0], perm, dept, sub)

    def _is_admin(self):
        # "Sysadmin" = tiene el permiso de gestión de usuarios (rol it_admin). Vía RBAC: ya no
        # se lee 'scope'. Todos los admins migraron a it_admin, así que el resultado es idéntico.
        return self._has("users.manage")

    def _configured(self):
        """True si la instalación ya tiene al menos un usuario (no es el primer arranque).
        Se cachea: una vez configurado, no se vuelve a consultar la BD."""
        if getattr(self.server, "configured", False):
            return True
        if db.count_users() > 0:
            self.server.configured = True
            return True
        return False

    def _license(self):
        return license_refresh(self.server)

    def _license_ok(self):
        return self._license()["status"] == license.VALID

    def _profile_data(self):
        me = self._username()
        u = db.get_user(me) or {}
        rol = "admin" if u.get("scope") == "admin" else ("head" if u.get("boss") else "member")
        mine = db.user_visible_departments(me)               # [{slug, name, role}]
        mine_slugs = {d["slug"] for d in mine}
        global_access = any(d.get("role") == "all" for d in mine) or rol in ("admin", "head")
        available = ([] if global_access else
                     [{"slug": d["slug"], "name": d["name"]} for d in db.list_departments()
                      if d["slug"] not in mine_slugs])
        admin = self._is_admin()
        return {"username": me, "role": rol, "mine": mine, "available": available,
                "pending": db.user_pending_requests(me), "global_access": global_access,
                "twofa": {**db.totp_status(me), "available": admin,
                          "required": admin and require_2fa_admins()}}

    def _render_blocked(self):
        st = self._license()
        detail = {license.EXPIRED: f"Caducó el {st.get('expires')}.",
                  license.MISSING: "No hay ninguna licencia instalada.",
                  license.INVALID: "La licencia instalada no es válida."}.get(st["status"], "")
        # Al terminar una PRUEBA (expired), invita a dar feedback. El producto no envía nada: solo
        # muestra un enlace; el admin rellena en su navegador (no se rompe "nada sale de tu red").
        pedir_feedback = st["status"] == license.EXPIRED and bool(FEEDBACK_URL)
        fb_btn = (f'<a class="btn2" href="{html.escape(FEEDBACK_URL)}" target="_blank" rel="noopener">'
                  'Contar mi experiencia</a>') if pedir_feedback else ""
        fb_msg = (" <br><br>¿Has probado Hylanlock estos días? <b>Tu opinión honesta —lo bueno y lo "
                  "malo— me ayuda muchísimo a mejorarlo.</b> Son 2 minutos.") if pedir_feedback else ""
        if self._is_admin():
            return render_blocked(
                "Licencia caducada o no activa",
                "El servicio está bloqueado, pero <b>tus datos están intactos</b>. Renueva la "
                "licencia para reactivarlo; puedes exportar tus datos en cualquier momento." + fb_msg,
                detail,
                fb_btn +
                '<a class="btn2" href="/admin/licencia">Ver / renovar licencia</a>'
                '<a class="btn2" href="/admin/export">Exportar datos</a>'
                '<a class="btn2" href="/logout">Cerrar sesión</a>')
        return render_blocked(
            "Servicio no disponible",
            "La licencia de Hylanlock ha caducado o no está activa. "
            "Contacta con el administrador de tu empresa.",
            detail,
            '<a class="btn2" href="/logout">Cerrar sesión</a>')

    def _username(self):
        u = self._current_user()
        return u[0] if u else None

    def _can_dep(self, slug, perm="dept.view"):
        """¿El usuario logueado tiene 'perm' sobre ese departamento, y está en la LAN?
        Por defecto 'dept.view' (la carpeta existe para él). Los handlers que hacen algo
        concreto piden su permiso: 'files.upload' al subir, 'files.list' al listar, etc."""
        user = self._username()
        return bool(user) and self._is_lan() and db.has_permission(user, perm, slug)

    def _mis_carpetas(self):
        """Claves de las carpetas cuyo CONTENIDO puede ver el usuario ('files.list').

        Un depositario queda fuera a propósito: no puede ver lo que hay, así que tampoco tiene
        sentido avisarle de que ha llegado algo."""
        me = self._username() or ""
        claves = []
        for d in db.user_visible_departments(me):
            if db.has_permission(me, "files.list", d["slug"]):
                claves.append((d["slug"], d["name"]))
        for sf in db.user_accessible_subfolders(me):
            if sf.get("can_list"):
                claves.append((f"{sf['dept_slug']}/{sf['slug']}", sf["name"]))
        return claves

    def _novedades(self):
        """Qué ha llegado nuevo desde la última vez que el usuario miró cada carpeta."""
        me = self._username() or ""
        carpetas = self._mis_carpetas()
        nombres = dict(carpetas)
        claves = [k for k, _ in carpetas]
        por_carpeta = db.folder_news(me, claves)
        items = db.list_news(me, claves, 30)
        for it in items:
            it["folder_name"] = nombres.get(it["folder"], it["folder"])
            dep, _, sub = it["folder"].partition("/")
            it["url"] = f"/dep/{dep}/sub/{sub}" if sub else f"/dep/{dep}"
        return {"total": sum(por_carpeta.values()),
                "por_carpeta": por_carpeta,
                "items": items}

    def _api_folders(self):
        """Carpetas accesibles en el formato del contrato público, con lo que se puede hacer en
        cada una. Una cuenta con rol 'depositor' NO aparece: no puede listar, así que para la API
        de lectura esa carpeta no existe. Sale del modelo, no hay que programarlo."""
        me = self._username() or ""
        out = []
        for d in db.user_visible_departments(me):
            if db.has_permission(me, "files.list", d["slug"]):
                out.append({"kind": "department", "path": d["slug"], "name": d["name"],
                            "can_download": db.has_permission(me, "files.download", d["slug"])})
        for sf in db.user_accessible_subfolders(me):
            if sf.get("can_list"):
                out.append({"kind": "subfolder",
                            "path": f"{sf['dept_slug']}/{sf['slug']}", "name": sf["name"],
                            "department": sf["dept_name"],
                            "can_download": sf.get("can_download", False)})
        return out

    def _sync_manifest(self):
        """Todo lo que el agente de sincronización puede traerse, en UNA sola llamada.

        Incluye una carpeta solo si el usuario tiene 'files.list' Y 'files.download' sobre ella:
        sin listar no sabe qué hay, y sin descargar no puede traérselo. Un depositario (buzón de
        entrega) NO aparece aquí — y es lo correcto: no puede ver ese contenido."""
        me = self._username() or ""
        folders = []

        recortado = False

        def add(kind, dep, sub, name, base):
            nonlocal recortado
            if not (db.has_permission(me, "files.list", dep, sub)
                    and db.has_permission(me, "files.download", dep, sub)):
                return
            ruta = f"{dep}/{sub}" if sub else dep
            # Tope por carpeta: una sola carpeta con 50.000 ficheros no puede convertir el
            # manifiesto en una respuesta de decenas de MB que además se pide cada pocos minutos.
            items, siguiente = self._list_dir(
                sub_dir(dep, sub) if sub else dep_dir(dep), limit=MANIFEST_FILES_PER_FOLDER)
            entrada = {
                "kind": kind, "dep": dep, "sub": sub, "name": name, "path": ruta,
                "download_url": (f"/dep/{dep}/sub/{sub}/download" if sub
                                 else f"/dep/{dep}/download"),
                "files": items,
            }
            if siguiente:
                # El cliente DEBE completar esta carpeta por /api/v1/files antes de dar la foto
                # por buena. El agente lo hace; para cualquier otro consumidor queda documentado.
                entrada["truncated"] = True
                entrada["next"] = siguiente
                recortado = True
            folders.append(entrada)

        for d in db.user_visible_departments(me):
            add("dep", d["slug"], None, d["name"], None)
        for sf in db.user_accessible_subfolders(me):
            add("sub", sf["dept_slug"], sf["slug"], sf["name"], None)

        return {"user": me,
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                # Bandera global para que el cliente sepa de un vistazo si esta respuesta es la
                # foto COMPLETA o le falta algo por pedir.
                "truncated": recortado,
                "folders": folders}

    def _render_folder(self, dep, sub=None):
        """Página de una carpeta: un DEPARTAMENTO (sub=None) o una SUBCARPETA. Misma plantilla
        para las dos; lo que cambia son las URLs y lo que ESTE usuario puede hacer aquí."""
        can_up = self._has("files.upload", dep, sub)
        can_ls = self._has("files.list", dep, sub)
        d = next((x for x in db.list_departments() if x["slug"] == dep), None)
        depname = d["name"] if d else dep

        if sub:
            sf = next((x for x in db.list_subfolders(dep) if x["slug"] == sub), None)
            title = sf["name"] if sf else sub
            icon, kind = ('<svg viewBox="0 0 24 24" width="24" height="24" fill="none" '
                          'stroke="currentColor" stroke-width="2" stroke-linecap="round" '
                          'stroke-linejoin="round"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 '
                          '2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>'), \
                "Subcarpeta de " + html.escape(depname)
            apibase, dlbase = f"/api/dep/{dep}/sub/{sub}", f"/dep/{dep}/sub/{sub}"
            upqs = f"zone=sub&dep={dep}&sub={sub}"
            # Volver al departamento solo si puede verlo: un depositario puede tener acceso a la
            # subcarpeta SIN ser miembro del departamento que la contiene.
            if self._has("dept.view", dep):
                back, backtxt = f"/dep/{dep}", "← " + html.escape(depname)
            else:
                back, backtxt = "/departamentos", "← Mis carpetas"
        else:
            title = depname
            icon, kind = ('<svg viewBox="0 0 24 24" width="24" height="24" fill="none" '
                          'stroke="currentColor" stroke-width="2" stroke-linecap="round" '
                          'stroke-linejoin="round"><rect x="4" y="3" width="16" height="18" rx="1"/>'
                          '<path d="M9 7h2M13 7h2M9 11h2M13 11h2M9 15h2M13 15h2"/></svg>'), \
                "Departamento · espacio compartido local"
            apibase, dlbase = f"/api/dep/{dep}", f"/dep/{dep}"
            upqs = f"zone=dep&dep={dep}"
            back, backtxt = "/departamentos", "← Departamentos"

        # Abrir la carpeta = darse por enterado de lo que hay. Solo si puede ver el contenido:
        # a un depositario no se le marca nada, porque tampoco se le avisa.
        if can_ls:
            db.mark_folder_seen(self._username() or "", f"{dep}/{sub}" if sub else dep)

        if can_up and not can_ls:
            aviso = ('<div class="notice-box"><b>Buzón de entrega.</b> Puedes dejar '
                     'archivos aquí, pero no ver los que ya hay. Es intencionado: el '
                     'contenido es privado de quien recibe.</div>')
        elif can_ls and not can_up:
            aviso = ('<div class="notice-box"><b>Solo lectura.</b> Puedes ver y '
                     'descargar los archivos, pero no subir.</div>')
        else:
            aviso = ""
        if sub:
            # Honestidad (decisión de Nicolás): nunca prometer una privacidad que no existe.
            aviso += ('<div class="notice-box"><b>Quién más puede ver esta carpeta:</b> '
                      'el jefe del departamento, la dirección y el administrador del sistema. '
                      'Es privada frente al resto de compañeros, no frente a la empresa.</div>')

        return self._shell(DEP_PAGE, "/departamentos", title,
                           __CRUMB__=f'<a class="crumb" href="{back}">{backtxt}</a>',
                           __ICON__=icon,
                           __KIND__=kind,
                           __DEPNAME__=html.escape(title),
                           __AVISO__=aviso,
                           __APIBASE__=apibase,
                           __DLBASE__=dlbase,
                           __UPQS__=upqs,
                           __D_UP__=("block" if can_up else "none"),
                           __D_LS__=("block" if can_ls else "none"),
                           __CAN_LIST__=("true" if can_ls else "false"),
                           __CAN_DELETE__=("true" if (can_ls and self._is_admin()) else "false"),
                           __DEP_SLUG__=json.dumps(dep), __SUB_SLUG__=json.dumps(sub or ""))

    def _render_subfolder(self, dep, sub):
        return self._render_folder(dep, sub)

    def _depts_visibles(self):
        """Departamentos que el usuario puede ver (RBAC). Etiqueta all/head/member para la UI."""
        return db.user_visible_departments(self._username() or "")

    # ---------- Shell de layout (barra lateral compartida) ----------
    def _nav_items(self, active):
        """Genera el menú lateral según el rol. 'active' marca la sección actual."""
        def link(route, icon, label, badge=0):
            cls = ' class="active"' if route == active else ""
            b = (f'<span class="nav-badge" title="{badge} archivo(s) nuevo(s)">{badge if badge < 100 else "99+"}</span>'
                 if badge else "")
            return (f'<a href="{route}"{cls}><span class="ic">{icon}</span> '
                    f'{html.escape(label)}{b}</a>')
        # Contador de novedades: se calcula aquí porque el menú va en TODAS las páginas.
        try:
            nuevas = db.folder_news(self._username() or "",
                                    [k for k, _ in self._mis_carpetas()])
            total_nuevas = sum(nuevas.values())
        except Exception:
            total_nuevas = 0
        parts = [link("/", _NAV_ICONS["home"], "Inicio", total_nuevas),
                 link("/departamentos", _NAV_ICONS["building"], "Departamentos", total_nuevas),
                 link("/perfil", _NAV_ICONS["user"], "Mi perfil"),
                 link("/ajustes", _NAV_ICONS["cog"], "Ajustes")]
        admin = []
        if self._is_admin():                       # users.manage (it_admin)
            admin.append(link("/admin", _NAV_ICONS["shield"], "Administración"))
        if self._is_admin():
            admin.append(link("/papelera", _NAV_ICONS["trash"], "Papelera"))
        if self._has("folder.oversee"):            # admins y rol Supervisor
            admin.append(link("/gobernanza", _NAV_ICONS["eye"], "Gobernanza"))
        if self._has("audit.view"):
            admin.append(link("/log", _NAV_ICONS["list"], "Registro"))
        if admin:
            parts.append('<div class="nav-lbl">Administración</div>')
            parts.extend(admin)
        return "\n".join(parts)

    def _license_banner(self):
        """Aviso discreto cuando la licencia es válida pero está a punto de caducar (<= 7 días)."""
        st = self._license()
        if st["status"] != license.VALID:
            return ""
        d = st.get("days_left")
        if d is None or d > 7:
            return ""
        cuando = "hoy" if d <= 0 else (f"en <b>{d} día(s)</b>")
        accion = (' · <a href="/admin/licencia" style="color:inherit;font-weight:700">Renovar</a>'
                  if self._is_admin() else "")
        return ('<div style="margin:0 0 16px;padding:10px 14px;border-radius:12px;font-size:.88rem;'
                'background:color-mix(in srgb, var(--warn) 14%, transparent);'
                'border:1px solid color-mix(in srgb, var(--warn) 40%, transparent);color:var(--warn)">'
                f'Tu licencia caduca {cuando}.{accion}</div>')

    def _exposure_banner(self):
        """Banner rojo para administradores si llegan conexiones desde internet sin revisar."""
        if not self._is_admin():
            return ""
        filas, pendientes = exposure_state()
        if not pendientes:
            return ""
        ultima = max(f["last"] for f in filas if not f["legit"])
        return ('<div id="expo-banner" style="margin:0 0 16px;padding:12px 14px;border-radius:12px;font-size:.88rem;'
                'background:color-mix(in srgb, var(--err) 12%, transparent);'
                'border:1px solid color-mix(in srgb, var(--err) 45%, transparent);color:var(--err)">'
                f'<b>⚠️ {html.escape(brand_name())} está recibiendo conexiones desde internet</b> '
                f'({pendientes} IP{"s" if pendientes != 1 else ""} nueva{"s" if pendientes != 1 else ""}, '
                f'la última {_hace(ultima)}). Está pensado para la red local: revisa si hay un puerto abierto '
                'en el router o un proxy publicado. '
                '<a href="/ajustes#exposicion" style="color:inherit;font-weight:700">Ver detalle</a> · '
                '<a href="#" style="color:inherit" onclick="fetch(\'/admin/exposicion/revisado\',{method:\'POST\'})'
                '.then(function(){var b=document.getElementById(\'expo-banner\');if(b)b.remove()});return false">'
                'Revisado</a></div>')

    def _exposure_card(self):
        """Tarjeta de Ajustes: estado de exposición a internet y lista de IPs vistas."""
        filas, pendientes = exposure_state()
        malas = [f for f in filas if not f["legit"]]
        aviso_cidr = ""
        if lan_cidrs_publicas():
            aviso_cidr = ('<div class="dsc" style="color:var(--err);margin-top:8px"><b>Configuración peligrosa:</b> '
                          f'HYLANLOCK_LAN_CIDR incluye IPs de internet ({html.escape(", ".join(lan_cidrs_publicas()))}), '
                          'así que internet cuenta como "red local". Acótalo a tus subredes privadas.</div>')
        if not filas:
            estado = ('<div class="dsc" style="color:var(--ok);margin-top:8px">✅ No se ha detectado ningún acceso '
                      f'desde internet en los últimos {EXPO_DAYS} días.</div>')
        else:
            estado = ('<div class="dsc" style="margin-top:8px">'
                      + (f'<b style="color:var(--err)">Se han recibido conexiones desde {len(malas)} IP(s) de internet.</b> '
                         'Hylanlock las rechaza, pero que lleguen significa que está expuesto: cierra el puerto en el '
                         'router o el proxy.' if malas else
                         'Solo hay accesos remotos <b>autorizados</b> a la API (cuentas con acceso remoto).')
                      + '</div>')
            filas_html = "".join(
                f'<tr><td style="font-family:monospace">{html.escape(f["ip"])}</td>'
                f'<td>{"API remota autorizada" if f["legit"] else "<b>no autorizado</b>"}</td>'
                f'<td>{_hace(f["first"])}</td><td>{_hace(f["last"])}</td><td>{int(f["count"])}</td>'
                f'<td style="font-family:monospace;word-break:break-all">{html.escape(f["path"])}</td></tr>'
                for f in filas)
            estado += ('<div style="overflow-x:auto;margin-top:10px"><table style="width:100%;font-size:.82rem;'
                       'border-collapse:collapse"><thead><tr style="text-align:left;color:var(--muted)">'
                       '<th>IP</th><th>Tipo</th><th>Primera vez</th><th>Última</th><th>Peticiones</th>'
                       f'<th>Última ruta</th></tr></thead><tbody>{filas_html}</tbody></table></div>')
            if pendientes:
                estado += ('<button class="mini" style="margin-top:10px" onclick="fetch(\'/admin/exposicion/revisado\','
                           '{method:\'POST\'}).then(function(){location.reload()})">Marcar como revisado</button>')
        return ('<h2 class="sec" id="exposicion">Exposición a internet</h2>'
                '<div class="aj-card"><div class="ttl">¿Se puede llegar a este Hylanlock desde fuera?</div>'
                '<div class="dsc">Se detecta de forma pasiva, sin consultar ningún servicio externo: si llega una '
                'petición desde una IP pública, está expuesto. Detrás de un proxy (Caddy), configura '
                'HYLANLOCK_TRUSTED_PROXIES para que se vea la IP real.</div>'
                f'{aviso_cidr}{estado}</div>')

    def _trash_card(self):
        dias = trash_days()
        return ('<h2 class="sec">Papelera</h2>'
                '<div class="aj-card"><div class="ttl">Días en la papelera antes de eliminarse</div>'
                '<div class="dsc">Lo que borra un administrador va a la <a href="/papelera">Papelera</a> y se puede '
                'restaurar en su sitio. Pasados estos días se elimina de verdad (queda en la auditoría). '
                '<b>0 = nunca se vacía sola</b> (útil si guardas documentos legales años).</div>'
                '<div style="display:flex;gap:10px;align-items:center;margin-top:12px;flex-wrap:wrap">'
                f'<input id="tr-days" type="number" min="0" max="3650" value="{dias}" style="width:110px">'
                '<span class="dsc" style="margin:0">días</span>'
                '<button class="mini" onclick="saveTrash()">Guardar</button>'
                '<span id="tr-msg" class="dsc" style="margin:0"></span></div></div>')

    def _twofa_card(self):
        """Ajustes: política de 2FA para administradores y quién lo tiene ya."""
        admins = [u for u in db.list_users() if u["scope"] == "admin"]
        con = [u["username"] for u in admins if u.get("totp")]
        sin = [u["username"] for u in admins if not u.get("totp")]
        on = require_2fa_admins()
        estado = (f'<b>{len(con)} de {len(admins)}</b> administradores lo tienen activado'
                  + (f' · sin 2FA: {html.escape(", ".join(sin))}' if sin else ' ✅'))
        return ('<h2 class="sec">Verificación en dos pasos (2FA)</h2>'
                '<div class="aj-card"><div class="ttl">Exigir 2FA a los administradores</div>'
                '<div class="dsc">Además de la contraseña, un código de 6 cifras de una app del móvil (Google '
                'Authenticator, Microsoft Authenticator, Aegis…). Cada administrador lo activa en <b>Mi perfil</b>. '
                'Si lo exiges, quien no lo tenga deberá configurarlo al entrar.</div>'
                '<label style="display:flex;gap:8px;align-items:center;margin-top:12px;cursor:pointer;font-size:.9rem">'
                f'<input type="checkbox" id="tf-policy" style="width:auto" {"checked" if on else ""} '
                'onchange="saveTwofa(this)"> Exigir 2FA a todos los administradores</label>'
                f'<div class="dsc" style="margin-top:8px">{estado}.</div>'
                '<span id="tf-msg" class="dsc"></span></div>')

    def _ajustes_admin_block(self):
        """Secciones de Ajustes SOLO para administradores: plan/licencia y seguridad. Para un
        miembro normal devuelve '' (solo ve tema, idioma y acerca de)."""
        if not self._is_admin():
            return ""
        st = self._license()
        status = st.get("status")
        if status == license.VALID and st.get("type") == "trial":
            nombre, color = f"Prueba — {st.get('days_left', '?')} día(s)", "var(--warn)"
            extra = f"Caduca el {html.escape(str(st.get('expires', '—')))}."
        elif status == license.VALID:
            nombre, color = "Comercial", "var(--ok)"
            extra = (f"Cliente: {html.escape(str(st.get('customer') or '—'))} · "
                     f"caduca {html.escape(str(st.get('expires', '—')))}.")
        elif status == license.EXPIRED:
            nombre, color = "Caducada", "var(--err)"
            extra = "El servicio está bloqueado. Instala una licencia nueva para reactivarlo."
        else:
            nombre, color = "Sin licencia", "var(--err)"
            extra = "El servicio está bloqueado hasta instalar una licencia."
        plan = (
            '<h2 class="sec">Plan y licencia</h2>'
            '<div class="aj-card"><div class="ttl">Plan de este Hylanlock</div>'
            f'<div style="margin-top:10px"><span class="planbadge" '
            f'style="background:color-mix(in srgb,{color} 16%,transparent);color:{color};'
            f'border:1px solid color-mix(in srgb,{color} 35%,transparent)">{html.escape(nombre)}</span></div>'
            f'<div class="dsc" style="margin-top:8px">{extra}</div>'
            '<a class="ajlink" href="/admin/licencia">Ver / instalar licencia &rarr;</a></div>'
        )
        seguridad = (
            '<h2 class="sec">Seguridad de subidas — extensiones bloqueadas</h2>'
            '<div class="aj-card">'
            '<div class="dsc">Marca los tipos de archivo que quieres <b>rechazar al subir</b>. Es una capa de '
            'higiene contra ejecutables/scripts que alguien podría abrir por error; renombrar la extensión la '
            'salta, así que no sustituye a un antivirus.</div>'
            '<div id="ext-groups" style="margin-top:10px"></div>'
            '<details style="margin-top:12px"><summary style="cursor:pointer;font-size:.85rem;color:var(--accent)">'
            'Otras extensiones (avanzado)</summary>'
            '<p style="font-size:.82rem;color:var(--muted);margin:8px 0 6px">Añade extensiones que no estén en la '
            'lista, separadas por comas (sin el punto).</p>'
            '<input id="ext-otras" type="text" style="width:100%;box-sizing:border-box;font-family:monospace;'
            'background:var(--surface-2);color:var(--text);border:1px solid var(--border);border-radius:10px;'
            'padding:9px 11px" placeholder="ej. iso, apk, run"></details>'
            '<div style="margin-top:12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">'
            '<button class="mini" onclick="saveExt()">Guardar</button>'
            '<button class="mini" onclick="extNone()">Desmarcar todo</button>'
            '<span id="ext-msg" style="font-size:.85rem;color:var(--muted)"></span></div></div>'
        )
        marca = (
            '<h2 class="sec">Marca blanca</h2>'
            '<div class="aj-card"><div class="ttl">Personaliza tu Hylanlock</div>'
            '<div class="dsc">Nombre, logo (un emoji o 1-2 letras; vacío = candado) y color de acento. '
            'Se aplica en toda la interfaz al guardar.</div>'
            '<div style="display:flex;flex-wrap:wrap;gap:10px;margin-top:12px;align-items:center">'
            f'<input id="mk-name" placeholder="Nombre" value="{html.escape(brand_name())}" style="flex:1;min-width:160px">'
            f'<input id="mk-logo" placeholder="Logo (emoji)" value="{html.escape(brand_logo() or "")}" maxlength="8" style="width:120px">'
            f'<input id="mk-accent" type="color" value="{brand_accent() if _valid_hex(brand_accent()) else "#1e40af"}" '
            'style="width:54px;height:40px;padding:3px" title="Color de acento">'
            '<button class="mini" onclick="saveMarca()">Guardar</button>'
            '<span id="mk-msg" class="dsc" style="width:100%;margin-top:2px"></span>'
            '</div></div>'
        )
        proximamente = ('<div class="softnote">Próximamente aquí: política de contraseñas y avisos.</div>')
        header = ('<div class="aj-group" style="margin-top:30px">Ajustes de la organización'
                  '<span> · solo administradores, afectan a toda la empresa</span></div>')
        return (header + plan + self._exposure_card() + self._twofa_card() + self._trash_card()
                + marca + seguridad + proximamente)

    def _shell(self, content_page, active, title, **markers):
        """Envuelve el fragmento 'content_page' con el shell (sidebar + contenido). El fragmento
        trae su propio <style>/<script>; aquí se rellenan el menú, el usuario y los marcadores."""
        user = self._username() or ""
        admin = self._is_admin()
        role = "Administrador · acceso total" if admin else "Miembro · red local"
        avatar = "" if admin else ""
        frag = self._license_banner() + self._exposure_banner() + _template(content_page)
        for k, v in markers.items():
            frag = frag.replace(k, v)
        doc = (_template(LAYOUT_PAGE)
               .replace("__CSS__", _template(CSS))
               .replace("__TITLE__", html.escape(title))
               .replace("__ORG__", html.escape(ORG_NAME))
               .replace("__NAV__", self._nav_items(active))
               .replace("__USER__", html.escape(user))
               .replace("__ROLE__", role)
               .replace("__AVATAR__", avatar)
               .replace("__CONTENT__", frag))
        return _inject_theme(doc).encode("utf-8")

    @staticmethod
    def _split_sub(rest):
        """Parte '<dep>/sub/<sub>[/download]' en (dep, sub, es_descarga). (None,None,False) si no
        tiene la forma de subcarpeta. Ambos trozos se sanean (nunca rutas ni traversal)."""
        if "/sub/" not in rest:
            return None, None, False
        dep, _, tail = rest.partition("/sub/")
        down = tail.endswith("/download")
        if down:
            tail = tail[:-len("/download")]
        dep = os.path.basename(dep)
        sub = os.path.basename(tail)
        if not dep or not sub or "/" in tail:
            return None, None, False
        return dep, sub, down

    def _match_guard(self, method, path):
        """Devuelve (guard, dept, sub) para la ruta, o (None, None, None) si no está en la política.
        Las rutas de SUBCARPETA se comprueban ANTES que las de departamento: comparten prefijo
        (/dep/…) y sufijo (…/download), así que el orden importa."""
        if method == "GET":
            if path in _GUARD_GET:
                return _GUARD_GET[path], None, None
            # --- subcarpetas: /dep/<dep>/sub/<sub>[/download] y /api/dep/<dep>/sub/<sub>
            if path.startswith("/api/dep/"):
                dep, sub, _ = self._split_sub(path[len("/api/dep/"):])
                if dep:
                    return _DEP_GUARD_LIST, dep, sub
            if path.startswith("/dep/"):
                dep, sub, down = self._split_sub(path[len("/dep/"):])
                if dep:
                    return (_DEP_GUARD_DOWNLOAD if down else _DEP_GUARD), dep, sub
            # --- departamento
            if path.startswith("/dep/") and path.endswith("/download"):
                return _DEP_GUARD_DOWNLOAD, os.path.basename(path[len("/dep/"):-len("/download")]), None
            if path.startswith("/api/dep/"):
                return _DEP_GUARD_LIST, os.path.basename(path[len("/api/dep/"):]), None
            if path.startswith("/dep/"):
                return _DEP_GUARD, os.path.basename(path[len("/dep/"):]), None
            return None, None, None
        if method == "POST":
            return _GUARD_POST.get(path), None, None
        return None, None, None

    def _enforce(self, method, path):
        """Chokepoint de autorización. Devuelve True si se permite; si no, ENVÍA la respuesta de
        denegación y devuelve False. Todas las rutas no públicas pasan por aquí."""
        # 1) Autenticación (toda ruta que llega aquí la exige).
        if not self._authed():
            if path.startswith(API_PREFIX):
                exposure_note(self._client_ip(), path)
            if method == "POST":
                self._read_body()                      # drenar el cuerpo para no romper keep-alive
                self._send(401, b"Auth", "text/plain; charset=utf-8")
            elif path.startswith("/api") or path.startswith("/upload"):
                self._send(401, b"Auth", "text/plain; charset=utf-8")
            else:
                self._send(302, extra=[("Location", "/login")])
            return False
        # 1a) Política "2FA obligatorio para administradores": un admin que entra por cookie y aún
        # no lo tiene configurado solo puede ir a Mi perfil a activarlo (o cerrar sesión).
        if (path not in TWOFA_SETUP_PATHS and require_2fa_admins() and self._cookie_user()
                and self._is_admin() and not db.totp_status(self._username())["enabled"]):
            if method == "POST":
                self._read_body()
            if method == "POST" or path.startswith("/api") or path.startswith("/upload"):
                self._send(403, "Tu organización exige la verificación en dos pasos: actívala en "
                                "Mi perfil.".encode("utf-8"), "text/plain; charset=utf-8")
            else:
                self._send(302, extra=[("Location", "/perfil?2fa=obligatorio")])
            return False
        # 1a-bis) Rate-limit de la API pública. Va aquí, en el chokepoint, para que valga igual
        # para todos los endpoints /api/v1 sin tener que acordarse en cada handler.
        if path.startswith(API_PREFIX):
            auth = self.headers.get("Authorization", "")
            # Huella por CLAVE si viene con token; si no (una persona probando con su sesión),
            # por usuario. Nunca se guarda el secreto: solo un hash corto.
            if auth.startswith("Bearer "):
                huella = hashlib.sha256(auth[7:].strip().encode()).hexdigest()[:16]
            else:
                huella = "u:" + (self._username() or "?")
            ok, n = api_rate_ok(huella)
            if not ok:
                self._api_error("rate_limited",
                                f"Demasiadas peticiones ({n} en el último minuto; "
                                f"el límite es {API_RATE_LIMIT}/min). Espera un momento.", 429)
                return False

        # 1b) CSRF: todo POST autenticado por cookie debe traer un token válido. El token va en el
        # formulario (__csrf__) o en la cabecera X-CSRF. (La futura API por token bearer irá exenta.)
        # Exención de CSRF para la API: SOLO en /api/v1 y SOLO si la petición se autentica
        # únicamente con token. Doble acotación a propósito — ni una petición con token puede
        # saltarse el CSRF fuera de la API, ni una petición con cookie puede saltárselo nunca.
        if method == "POST" and path.startswith(API_PREFIX) and self._solo_bearer():
            pass
        elif method == "POST":
            user = self._username()
            tv = (db.get_user(user) or {}).get("token_version", 1)
            want = csrf_token(self.server.session_token, user, tv)
            ct = self.headers.get("Content-Type", "")
            # La cabecera X-CSRF (fetch/XHR) tiene prioridad; así NUNCA se toca el cuerpo en las
            # rutas de streaming (subida). Solo si no hay cabecera y el cuerpo es un formulario, se
            # busca el campo __csrf__ en él.
            got = self.headers.get("X-CSRF", "")
            read_form = (not got) and ct.startswith("application/x-www-form-urlencoded")
            if read_form:
                got = parse_qs(self._read_body().decode("utf-8", "replace")).get("__csrf__", [""])[0]
            if not (want and hmac.compare_digest(got, want)):
                if not read_form:
                    self.close_connection = True   # no drenar cuerpos grandes (p. ej. chunk)
                self._send(403, b"CSRF", "text/plain; charset=utf-8")
                return False
        # 1c) Licencia: si NO es válida (caducada/ausente/corrupta) se bloquea el USO. El admin conserva
        #     el acceso a la pantalla de licencia y a EXPORTAR datos; nunca se tocan los datos del cliente.
        if not self._license_ok():
            if not (path in LICENSE_BYPASS_ADMIN and self._is_admin()):
                if method == "POST":
                    self._read_body()
                    self._send(403, b"Licencia no valida", "text/plain; charset=utf-8")
                elif path.startswith("/api") or path.startswith("/upload"):
                    self._send(403, b"Licencia no valida", "text/plain; charset=utf-8")
                else:
                    self._send(200, self._render_blocked())
                return False
        # 2) Guard de la ruta. FAIL-CLOSED (A1): si la ruta NO está declarada en la política, se
        # DENIEGA aquí con 404 en vez de dejarla pasar. Toda ruta legítima tiene su guarda (verificado
        # en la auditoría 2026-08), así que esto no cambia el comportamiento actual —las rutas
        # desconocidas ya devolvían 404—, pero convierte una futura ruta a la que se OLVIDE ponerle
        # guarda en un fallo VISIBLE (deja de funcionar) en vez de una exposición silenciosa.
        guard, dept, sub = self._match_guard(method, path)
        if guard is None:
            if method == "POST":
                self._read_body()                      # drenar el cuerpo para no romper keep-alive
            self._send(404, b"No encontrado", "text/plain; charset=utf-8")
            return False
        # 3) Candado LAN.
        if guard.get("lan") and not self._is_lan():
            # Excepción ACOTADA A LA API PÚBLICA: una integración puede salir del candado si su
            # cuenta de servicio tiene 'remote.access' concedido a mano. Se limita a /api/v1 a
            # propósito: la aplicación web sigue siendo estrictamente solo-LAN para todos,
            # incluido el administrador. Ampliarlo a la web cambiaría la promesa del producto.
            remoto_ok = path.startswith(API_PREFIX) and self._has("remote.access")
            if path.startswith(API_PREFIX):
                exposure_note(self._client_ip(), path, legit=remoto_ok)
            if not remoto_ok:
                if method == "POST":
                    self._read_body()
                if path.startswith(API_PREFIX):
                    self._api_error("forbidden",
                                    "Esta clave solo funciona desde la red local. Pide al "
                                    "administrador que le conceda acceso remoto si lo necesita.",
                                    403)
                else:
                    self._send(403, b"Solo desde la red local", "text/plain; charset=utf-8")
                return False
        # 4) Permiso RBAC (opcionalmente sobre el departamento capturado).
        perm = guard.get("perm")
        if perm and not self._has(perm, dept, sub):
            if method == "POST":
                self._read_body()
            redir = guard.get("deny_redirect")
            if redir:
                self._send(302, extra=[("Location", redir)])
            else:
                self._send(403, b"Sin permiso", "text/plain; charset=utf-8")
            return False
        # 5) Step-up / sudo: acciones privilegiadas exigen re-autenticación reciente.
        if guard.get("elevated") and not self._is_elevated():
            if method == "GET":
                self._send(302, extra=[("Location", "/elevate?next=" + quote(path))])
            else:
                self._read_body()
                self._send(403, b"Requiere re-autenticacion (step-up)", "text/plain; charset=utf-8")
            return False
        return True

    def _read_body(self):
        # Cachea el cuerpo: _enforce puede leerlo (para el token CSRF de un formulario) y luego el
        # handler vuelve a pedirlo. Se lee del socket una sola vez. Reset por petición en do_GET/do_POST.
        if getattr(self, "_body_cache", None) is None:
            length = int(self.headers.get("Content-Length", 0))
            self._body_cache = self.rfile.read(length) if length else b""
        return self._body_cache

    def _query(self):
        return parse_qs(urlparse(self.path).query)

    # -------------------------------------------------- GET
    def do_GET(self):
        self._body_cache = None
        path = urlparse(self.path).path
        if not path.startswith(API_PREFIX):
            exposure_note(self._client_ip(), path)
        trash_purge_if_due()          # papelera: vaciado automático, como mucho una vez por hora

        # Sonda de salud (Docker/monitorización): SIEMPRE 200 mientras el proceso sirva, sin importar
        # licencia, configuración o red. No expone datos.
        if path == "/healthz":
            self._send(200, b"ok", "text/plain; charset=utf-8")
            return

        # PWA (instalar como app): manifest, service worker e iconos. Son estáticos PÚBLICOS y sin
        # datos: se piden desde login/setup también, así que van aquí (sin candado LAN ni login).
        if path == "/manifest.webmanifest":
            self._send(200, PWA_MANIFEST, "application/manifest+json; charset=utf-8",
                       extra=[("Cache-Control", "public, max-age=86400")])
            return
        if path == "/sw.js":
            self._send(200, PWA_SW_JS, "application/javascript; charset=utf-8",
                       extra=[("Cache-Control", "no-cache"), ("Service-Worker-Allowed", "/")])
            return
        if path in ("/icon-192.png", "/icon-512.png"):
            try:
                with open(os.path.join(WEB_DIR, path.lstrip("/")), "rb") as _f:
                    _ico = _f.read()
                self._send(200, _ico, "image/png",
                           extra=[("Cache-Control", "public, max-age=604800")])
            except OSError:
                self._send(404, b"", "text/plain; charset=utf-8")
            return

        # Primer arranque: sin ningún usuario, el asistente de instalación toma el control.
        if not self._configured():
            if path == "/setup":
                if not self._is_lan():
                    self._send(403, b"Solo desde la red local", "text/plain; charset=utf-8")
                else:
                    self._send(200, render_setup())
            else:
                self._send(302, extra=[("Location", "/setup")])
            return
        if path == "/setup":                       # ya configurado -> el asistente no aplica
            self._send(302, extra=[("Location", "/login")])
            return

        if path == "/login":
            if self._authed():
                self._send(302, extra=[("Location", "/")])
            else:
                self._send(200, render(LOGIN_PAGE, err=""))
            return

        if path == "/login/2fa":
            if parse_2fa_pending(self.server.session_token, self._cookie_value("pr_2fa")):
                self._send(200, render_twofa())
            else:
                self._send(302, extra=[("Location", "/login")])
            return

        if path == "/logout":
            # Borra la cookie de ESTE navegador y manda al login.
            db.log_event("logout", origin=self._origin(), ip=self._client_ip())
            self._send(302, extra=[("Location", "/login"),
                                    ("Set-Cookie", expire_cookie())])
            return

        if path == "/activar":
            # Pantalla PÚBLICA (sin login) para poner la contraseña con un token de invitación.
            # Exige LAN: el secreto es el token, pero además se restringe a la red local.
            if not self._is_lan():
                self._send(403, b"Solo desde la red local", "text/plain; charset=utf-8")
                return
            token = self._query().get("token", [""])[0]
            inv = db.peek_invitation(token)
            if not inv:
                self._send(200, render_activate(err="Este enlace no es válido o ha caducado. "
                                                "Pide uno nuevo a tu administrador.", formcls="hide"))
            else:
                self._send(200, render_activate(inv["username"], token))
            return

        if path.startswith("/b/"):
            # Página PÚBLICA de un enlace de buzón: SOLO zona de soltar. Mismo molde que /activar:
            # el secreto es el token, pero además se exige red local. Y respeta la licencia.
            if not self._is_lan():
                self._send(403, b"Solo desde la red local", "text/plain; charset=utf-8")
                return
            token = path[len("/b/"):].split("/")[0]
            link = db.peek_buzon_link(token) if token else None
            if not link or not self._license_ok():
                self._send(200, render_buzon_drop(ok=False))
                return
            self._send(200, render_buzon_drop(ok=True, token=token, label=link["label"]))
            return

        # Autorización centralizada (auth + LAN + permiso RBAC) según la política de rutas.
        if not self._enforce("GET", path):
            return

        if path in ("/", "/index.html"):
            # Home = pantalla de bienvenida (guía rápida). Sirve para cualquier rol.
            me = self._username() or ""
            nombre = (me.split("@")[0].split(".")[0] or me).capitalize()
            conn = ("Conectado · red local" if self._is_lan()
                    else "Conectado · acceso remoto")
            self._send(200, self._shell(WELCOME_PAGE, "/", "Inicio",
                                        __HELLONAME__=html.escape(nombre),
                                        __CONN__=conn))
        elif path == "/departamentos":
            self._send(200, self._shell(DEPTS_PAGE, "/departamentos", "Departamentos"))
        elif path == "/perfil":
            self._send(200, self._shell(PROFILE_PAGE, "/perfil", "Mi perfil"))
        elif path == "/papelera":
            trash_purge_expired()     # al mirarla, que no salga nada que ya debería haberse ido
            dias = trash_days()
            items = db.trash_list()
            for it in items:
                ts = _gov_ts(it["deleted_at"])
                it["deleted_ts"] = ts
                it["purge_ts"] = (ts + dias * 86400) if (ts and dias) else None
                it["folder"] = f'{it["dept_slug"]}/{it["sub_slug"]}' if it["sub_slug"] else it["dept_slug"]
            datos = json.dumps({"items": items, "days": dias}, ensure_ascii=False).replace("</", "<\\/")
            self._send(200, self._shell(PAPELERA_PAGE, "/papelera", "Papelera", __TRASHDATA__=datos))
        elif path == "/gobernanza":
            # '</' escapado: el JSON va dentro de un <script> y un nombre de carpeta con "</script>"
            # no debe poder cerrarlo.
            datos = json.dumps(governance_snapshot(), ensure_ascii=False).replace("</", "<\\/")
            self._send(200, self._shell(GOBERNANZA_PAGE, "/gobernanza", "Gobernanza", __GOVDATA__=datos))
        elif path == "/ajustes":
            self._send(200, self._shell(AJUSTES_PAGE, "/ajustes", "Ajustes",
                                        __VERSION__=html.escape(APP_VERSION),
                                        __ADMINBLOCK__=self._ajustes_admin_block()))
        elif path == "/api/perfil":
            self._json(self._profile_data())
        elif path == "/api/admin/requests":
            self._json(db.list_access_requests("pending"))
        elif path == "/elevate":
            self._send(200, render_stepup(_safe_next(self._query().get("next", [""])[0]),
                                          need_code=db.totp_status(self._username() or "")["enabled"]))
        elif path == "/api/departamentos":
            self._send(200, json.dumps(self._depts_visibles()).encode("utf-8"),
                       "application/json; charset=utf-8")
        elif path == "/api/novedades":
            self._send(200, json.dumps(self._novedades()).encode("utf-8"),
                       "application/json; charset=utf-8")
        elif path == "/api/perfil/tokens":
            self._send(200, json.dumps(
                db.list_device_tokens(self._username() or "")).encode("utf-8"),
                "application/json; charset=utf-8")
        elif path == "/api/v1/openapi.json":
            self._send(200, json.dumps(openapi_spec(), ensure_ascii=False, indent=2)
                       .encode("utf-8"), "application/json; charset=utf-8")
        elif path == "/api/v1/whoami":
            # Existe para que integrar sea depurable: "¿por qué no veo esa carpeta?" se responde
            # con una llamada, en vez de mirando la base de datos.
            me = self._username() or ""
            u = db.get_user(me) or {}
            self._send(200, json.dumps({
                "user": me,
                "kind": "service" if u.get("scope") == "service" else "person",
                "auth": "token" if self.headers.get("Authorization", "").startswith("Bearer ")
                        else "session",
                "remote_allowed": db.has_permission(me, "remote.access"),
                "folders": [f["path"] for f in self._api_folders()],
            }).encode("utf-8"), "application/json; charset=utf-8")
        elif path == "/api/v1/folders":
            self._send(200, json.dumps({"folders": self._api_folders()}).encode("utf-8"),
                       "application/json; charset=utf-8")
        elif path == "/api/v1/files":
            me = self._username() or ""
            q = self._query()
            dep, sub, base = self._api_folder(q.get("folder", [""])[0])
            if not dep:
                self._api_error("bad_request",
                                "Falta 'folder' o no tiene forma válida ('depto' o 'depto/subcarpeta').",
                                400)
            elif not db.has_permission(me, "files.list", dep, sub):
                # Mismo 403 exista o no la carpeta: no se filtra qué carpetas hay.
                self._api_error("forbidden", "Esta clave no puede listar esa carpeta.", 403)
            else:
                limit = _pagina_pedida(q)
                items, siguiente = self._list_dir(
                    base, limit=limit, after=_cursor_decode(q.get("cursor", [""])[0]),
                    query=q.get("q", [""])[0])
                cuerpo = {
                    "folder": f"{dep}/{sub}" if sub else dep,
                    "files": items,
                    # 'has_more' además del cursor: quien no implemente paginación al menos puede
                    # DARSE CUENTA de que le falta media carpeta, en vez de creer que la tiene entera.
                    "has_more": siguiente is not None,
                }
                if siguiente:
                    cuerpo["next"] = siguiente
                self._send(200, json.dumps(cuerpo).encode("utf-8"),
                           "application/json; charset=utf-8")
        elif path == "/api/v1/download":
            me = self._username() or ""
            q = self._query()
            dep, sub, base = self._api_folder(q.get("folder", [""])[0])
            if not dep:
                self._api_error("bad_request", "Falta 'folder' o no tiene forma válida.", 400)
            elif not db.has_permission(me, "files.download", dep, sub):
                self._api_error("forbidden", "Esta clave no puede descargar de esa carpeta.", 403)
            elif not q.get("file", [""])[0]:
                self._api_error("bad_request", "Falta 'file'.", 400)
            else:
                # Reutiliza el mismo handler que la web: rangos, X-Content-SHA256, anti-traversal
                # y registro en auditoría con la carpeta de origen. Una sola implementación.
                self._handle_download(base, f"{dep}/{sub}" if sub else dep, api=True)
        elif path == "/api/v1/sync/manifest":
            self._send(200, json.dumps(self._sync_manifest()).encode("utf-8"),
                       "application/json; charset=utf-8")
        elif path == "/api/subcarpetas":
            # Todas las subcarpetas a las que llega el usuario, de cualquier depto. Necesario
            # porque un depositario puede no ser miembro del departamento que las contiene.
            self._send(200, json.dumps(
                db.user_accessible_subfolders(self._username() or "")).encode("utf-8"),
                "application/json; charset=utf-8")
        elif path.startswith("/api/dep/") and "/sub/" in path:
            dep, sub, _ = self._split_sub(path[len("/api/dep/"):])
            self._send(200, json.dumps(self._list_files(sub_dir(dep, sub))).encode("utf-8"),
                       "application/json; charset=utf-8")
        elif path.startswith("/api/dep/"):
            slug = os.path.basename(path[len("/api/dep/"):])
            self._send(200, json.dumps(self._list_files(dep_dir(slug))).encode("utf-8"),
                       "application/json; charset=utf-8")
        elif path.startswith("/dep/") and "/sub/" in path:
            dep, sub, down = self._split_sub(path[len("/dep/"):])
            if down:
                self._handle_download(sub_dir(dep, sub), f"{dep}/{sub}")
            else:
                self._send(200, self._render_subfolder(dep, sub))
        elif path.startswith("/dep/"):
            rest = path[len("/dep/"):]
            if rest.endswith("/download"):
                slug = os.path.basename(rest[:-len("/download")])
                self._handle_download(dep_dir(slug), slug)
            else:
                self._send(200, self._render_folder(os.path.basename(rest)))
        elif path == "/admin":
            self._send(200, self._shell(ADMIN_PAGE, "/admin", "Administración"))
        elif path == "/api/admin/users":
            self._send(200, json.dumps(db.list_users()).encode("utf-8"),
                       "application/json; charset=utf-8")
        elif path == "/api/admin/services":
            self._send(200, json.dumps(db.list_service_accounts()).encode("utf-8"),
                       "application/json; charset=utf-8")
        elif path == "/api/admin/subfolders":
            dep = os.path.basename(self._query().get("dep", [""])[0])
            self._send(200, json.dumps([
                dict(sf, acl=db.subfolder_acl(dep, sf["slug"]),
                     links=db.list_buzon_links(dep, sf["slug"]))
                for sf in db.list_subfolders(dep)
            ]).encode("utf-8"), "application/json; charset=utf-8")
        elif path == "/api/admin/departments":
            deps = [{"name": d["name"], "slug": d["slug"],
                     "members": db.department_members(d["slug"])}
                    for d in db.list_departments()]
            self._send(200, json.dumps(deps).encode("utf-8"),
                       "application/json; charset=utf-8")
        elif path == "/api/admin/config":
            # Política de contraseñas (Parte A) para que la UI se adapte a lo que decida la empresa.
            self._json({"method": PW_METHOD, "allow_direct": ALLOW_DIRECT_PW,
                        "min_password": MIN_PASSWORD, "invite_hours": INVITE_HOURS,
                        "blocked_ext": sorted(blocked_ext_set())})
        elif path == "/admin/licencia":
            self._send(200, render_license(self._license()))
        elif path == "/api/admin/license":
            st = self._license()
            self._json({"status": st["status"], "customer": st.get("customer"),
                        "type": st.get("type"), "expires": st.get("expires"),
                        "days_left": st.get("days_left")})
        elif path == "/admin/export":
            self._handle_export()
        elif path == "/log":
            summary, rows, filtros = log_markers(self._query())
            self._send(200, self._shell(LOG_PAGE, "/log", "Registro",
                                        __SUMMARY__=summary, __ROWS__=rows,
                                        __FILTROS__=filtros))
        elif path == "/log.csv":
            data, _n = build_log_csv(self._query())
            fname = "hylanlock-registro-" + time.strftime("%Y%m%d-%H%M") + ".csv"
            self._send(200, data, "text/csv; charset=utf-8",
                       extra=[("Content-Disposition", 'attachment; filename="%s"' % fname)])
        elif path == "/api/log":
            # Mismos filtros que la pantalla (?desde=&hasta=&tipo=&usuario=&q=), para que no
            # existan dos formas distintas de consultar lo mismo.
            q = self._query()
            def _f(k):
                return ((q.get(k, [""])[0] or "").strip().replace("T", " ")) or None
            try:
                lim = min(max(int(q.get("limite", ["200"])[0]), 1), 1000)
            except ValueError:
                lim = 200
            self._send(200, json.dumps(db.search_events(
                limit=lim, desde=_f("desde"), hasta=_f("hasta"), tipo=_f("tipo"),
                usuario=_f("usuario"), texto=_f("q"))).encode("utf-8"),
                "application/json; charset=utf-8")
        elif path == "/upload/status":
            q = self._query()
            uid = safe_id(q.get("id", [""])[0])
            received = 0
            if uid:
                part = os.path.join(PART_DIR, uid + ".part")
                if os.path.exists(part):
                    received = os.path.getsize(part)
            self._send(200, json.dumps({"received": received}).encode("utf-8"),
                       "application/json; charset=utf-8")
        else:
            self._send(404, b"No encontrado", "text/plain; charset=utf-8")

    # -------------------------------------------------- POST
    def do_POST(self):
        self._body_cache = None
        path = urlparse(self.path).path
        if not path.startswith(API_PREFIX):
            exposure_note(self._client_ip(), path)

        # Primer arranque: el asistente crea el administrador (y opcionalmente instala la licencia).
        if not self._configured():
            if path == "/setup":
                self._handle_setup()
            else:
                self._read_body()
                self._send(302, extra=[("Location", "/setup")])
            return

        if path == "/login":
            ip = self._client_ip()
            # Anti-fuerza-bruta: si la IP está bloqueada, ni miramos la contraseña.
            if login_blocked(ip):
                self._read_body()
                err = ('<div class="err-msg">Demasiados intentos fallidos. '
                       'Espera unos minutos e inténtalo de nuevo.</div>')
                self._send(429, render(LOGIN_PAGE, err=err))
                return
            body = self._read_body().decode("utf-8", "replace")
            data = parse_qs(body)
            username = data.get("username", [""])[0].strip()
            given = data.get("password", [""])[0]
            remember = data.get("remember", [""])[0] == "on"
            scope = db.verify_user(username, given) if username else None
            # Si el login LOCAL no valida y AD está activado, probar contra el directorio.
            # (El admin local se comprueba primero: nunca te quedas fuera aunque el AD falle.)
            if scope is None and username and LDAP_ENABLED:
                res = ldap_auth.ldap_login(LDAP_CONFIG, username, given)
                if isinstance(res, dict):
                    # El directorio autenticó, pero el nombre puede pertenecer a una cuenta LOCAL.
                    # En ese caso NO se entra: la cuenta local es dueña de su nombre y solo se abre
                    # con SU contraseña (que ya se comprobó antes y falló). Si no, cualquiera que
                    # pueda crear un usuario en el directorio se apoderaría de una cuenta de aquí.
                    if db.upsert_ldap_user(res["username"], scope=res["scope"],
                                           boss=res["boss"]) is None:
                        db.log_event("login_fail", user=username, origin=self._origin(), ip=ip,
                                     detail="nombre en conflicto: ya existe una cuenta local")
                        notify_telegram(
                            f"SEGURIDAD: el directorio autenticó a «{username}», pero ese "
                            f"nombre ya es de una cuenta LOCAL. Acceso denegado.\n"
                            f"Hora: {time.strftime('%H:%M')}")
                    else:
                        db.sync_ldap_memberships(res["username"], res["memberships"])
                        scope = res["scope"]
                        db.log_event("login_ldap", user=username, origin=self._origin(), ip=ip)
            deny = None
            # Política de red (decisión 1): sin estar en la LAN, solo entran quienes tengan el
            # permiso 'remote.access' (por defecto el admin/it_admin; concedible a un usuario/boss).
            if scope and not self._is_lan() and not db.has_permission(username, "remote.access"):
                scope = None
                deny = "usuario sin acceso remoto desde fuera"
            if scope and db.totp_status(username)["enabled"]:
                # Contraseña correcta, pero la cuenta tiene 2FA: aún NO hay sesión. Los fallos de
                # la IP no se limpian hasta que acierte también el código.
                pend = make_2fa_pending(self.server.session_token, username, scope, remember)
                self._send(200, render_twofa(), extra=[("Set-Cookie", twofa_cookie(pend, self._tls()))])
            elif scope:
                self._finish_login(username, scope, remember, ip)
            else:
                n = record_login_fail(ip)
                db.log_event("login_fail", user=username or None,
                             origin=self._origin(), ip=ip,
                             detail=deny or f"intento {n}")
                if deny:
                    notify_telegram(f"SEGURIDAD: intento de acceso desde fuera de la red local\n"
                                    f"Usuario: {username}\nHora: {time.strftime('%H:%M')}")
                if n >= LOGIN_MAX_FAILS:
                    db.log_event("brute_block", origin=self._origin(), ip=ip)
                    notify_telegram(f"SEGURIDAD: bloqueo por fuerza bruta\n"
                                    f"IP: {ip}\nHora: {time.strftime('%H:%M')}")
                time.sleep(min(n, 5) * 0.4)   # retardo progresivo (cap 2s)
                msg = ("Esta cuenta solo puede entrar desde la red local de la empresa"
                       if deny else "Usuario o contraseña incorrectos")
                err = f'<div class="err-msg">{msg}</div>'
                self._send(200, render(LOGIN_PAGE, err=err))
            return

        if path == "/login/2fa":
            # Segundo paso del login. Solo vale con la cookie intermedia (contraseña ya acertada).
            ip = self._client_ip()
            data = parse_qs(self._read_body().decode("utf-8", "replace"))
            pend = parse_2fa_pending(self.server.session_token, self._cookie_value("pr_2fa"))
            if not pend:
                self._send(302, extra=[("Location", "/login")])
                return
            username, scope, remember = pend
            if login_blocked(ip):
                self._send(429, render_twofa('<div class="err-msg">Demasiados intentos fallidos. '
                                             'Espera unos minutos e inténtalo de nuevo.</div>'))
                return
            res = db.totp_check(username, data.get("code", [""])[0])
            if res:
                detalle = "2FA"
                if res == "recovery":
                    quedan = db.totp_status(username)["recovery_left"]
                    detalle = f"2FA con código de recuperación (quedan {quedan})"
                    notify_telegram(f"SEGURIDAD: {username} ha entrado con un código de recuperación "
                                    f"del 2FA (le quedan {quedan}).\nHora: {time.strftime('%H:%M')}")
                self._finish_login(username, scope, remember, ip, detail=detalle, clear_2fa=True)
            else:
                n = record_login_fail(ip)
                db.log_event("login_fail", user=username, origin=self._origin(), ip=ip,
                             detail=f"código 2FA incorrecto (intento {n})")
                if n >= LOGIN_MAX_FAILS:
                    db.log_event("brute_block", origin=self._origin(), ip=ip)
                    notify_telegram(f"SEGURIDAD: bloqueo por fuerza bruta (2FA)\n"
                                    f"IP: {ip}\nHora: {time.strftime('%H:%M')}")
                time.sleep(min(n, 5) * 0.4)
                self._send(200, render_twofa('<div class="err-msg">Código incorrecto o ya usado</div>'))
            return

        if path == "/activar":
            # Canje PÚBLICO del token de invitación: el usuario fija su contraseña. Exige LAN.
            if not self._is_lan():
                self._read_body()
                self._send(403, b"Solo desde la red local", "text/plain; charset=utf-8")
                return
            d = parse_qs(self._read_body().decode("utf-8", "replace"))
            token = d.get("token", [""])[0]
            pw = d.get("password", [""])[0]
            pw2 = d.get("password2", [""])[0]
            inv = db.peek_invitation(token)
            if not inv:
                self._send(200, render_activate(err="Este enlace no es válido o ha caducado.",
                                                formcls="hide"))
            elif len(pw) < MIN_PASSWORD:
                self._send(200, render_activate(inv["username"], token,
                                                err=f'<div class="err-msg">La contraseña debe tener al menos {MIN_PASSWORD} caracteres.</div>'))
            elif pw != pw2:
                self._send(200, render_activate(inv["username"], token,
                                                err='<div class="err-msg">Las contraseñas no coinciden.</div>'))
            else:
                ok, res = db.redeem_invitation(token, pw)
                if ok:
                    db.log_event("account_activated", user=res, origin=self._origin(),
                                 ip=self._client_ip())
                    self._send(302, extra=[("Location", "/login?activated=1")])
                else:
                    self._send(200, render_activate(inv["username"], token,
                                                    err=f'<div class="err-msg">{html.escape(res)}</div>',
                                                    formcls="hide"))
            return

        if path.startswith("/b/") and (path.endswith("/chunk") or path.endswith("/complete")):
            # Entrega PÚBLICA por enlace de buzón (sin login). Seguridad propia: LAN + licencia +
            # token válido + rate-limit + bloqueo de extensiones + tope de temporales.
            self._handle_buzon_drop(path)
            return

        # Autorización centralizada (auth + LAN + permiso RBAC) según la política de rutas.
        if not self._enforce("POST", path):
            return

        if path == "/upload/chunk":
            self._handle_chunk()
        elif path == "/upload/complete":
            self._handle_complete()
        elif path == "/logout-all":
            self._read_body()
            me = (self._current_user() or (None,))[0]
            db.log_event("logout_all", user=me, origin=self._origin(), ip=self._client_ip())
            # Sube el token_version de ESTE usuario -> invalida SOLO sus cookies, en todos sus
            # equipos (ya no echa a los demás usuarios como antes).
            if me:
                db.bump_token_version(me)
            self._send(302, extra=[("Location", "/login"),
                                    ("Set-Cookie", expire_cookie())])
        elif path == "/elevate":
            d = parse_qs(self._read_body().decode("utf-8", "replace"))
            nxt = _safe_next(d.get("next", [""])[0])
            me = self._username()
            ip = self._client_ip()
            need_code = bool(me) and db.totp_status(me)["enabled"]
            if login_blocked(ip):
                # Mismo freno que el login: sin él, el código de 6 cifras se podría adivinar aquí.
                self._send(429, render_stepup(nxt, '<div class="err-msg">Demasiados intentos fallidos. '
                                                   'Espera unos minutos.</div>', need_code))
                return
            scope = db.verify_user(me, d.get("password", [""])[0]) if me else None
            if scope and need_code and not db.totp_check(me, d.get("code", [""])[0]):
                scope = None
            if scope:
                clear_login_fails(ip)
                tv = (db.get_user(me) or {}).get("token_version", 1)
                elev = int(time.time()) + STEPUP_MINUTES * 60
                rem = self._session_field(4)   # idx 4 = "recordarme"; conserva la persistencia
                value = make_session(self.server.session_token, me, scope, tv, elev, rem)
                db.log_event("stepup_ok", user=me, origin=self._origin(), ip=self._client_ip())
                # Re-emite la cookie ELEVADA conservando la persistencia original (recordarme).
                self._send(302, extra=[("Location", nxt),
                                       ("Set-Cookie", session_cookie(value, bool(rem), secure=self._tls()))])
            else:
                n = record_login_fail(ip)
                db.log_event("stepup_fail", user=me, origin=self._origin(), ip=ip, detail=f"intento {n}")
                if n >= LOGIN_MAX_FAILS:
                    db.log_event("brute_block", origin=self._origin(), ip=ip)
                    notify_telegram(f"SEGURIDAD: bloqueo por fuerza bruta (step-up de {me})\n"
                                    f"IP: {ip}\nHora: {time.strftime('%H:%M')}")
                time.sleep(min(n, 5) * 0.4)
                msg = "Contraseña o código incorrectos" if need_code else "Contraseña incorrecta"
                self._send(200, render_stepup(nxt, f'<div class="err-msg">{msg}</div>', need_code))
        elif path == "/admin/config/extensiones":
            d = parse_qs(self._read_body().decode("utf-8", "replace"))
            me = (self._current_user() or (None,))[0]
            guardadas = set_blocked_ext(d.get("ext", [""])[0])
            db.log_event("config_blocked_ext", user=me, origin=self._origin(),
                         ip=self._client_ip(), detail=f"{len(guardadas)} extensiones bloqueadas")
            self._json({"ok": True, "blocked_ext": sorted(guardadas)})
        elif path == "/admin/exposicion/revisado":
            self._read_body()
            me = (self._current_user() or (None,))[0]
            db.meta_set(EXPO_ACK_KEY, str(time.time()))
            db.log_event("exposure_ack", user=me, origin=self._origin(), ip=self._client_ip(),
                         detail=f"{len(exposure_state()[0])} IP(s) de internet revisadas")
            self._json({"ok": True})
        elif path == "/admin/config/marca":
            d = parse_qs(self._read_body().decode("utf-8", "replace"))
            me = (self._current_user() or (None,))[0]
            acc = d.get("accent", [""])[0].strip()
            if acc and not _valid_hex(acc):
                self._json({"error": "Color no válido (usa #rrggbb)"}, 400)
            else:
                set_branding(name=d.get("name", [""])[0], logo=d.get("logo", [""])[0], accent=acc)
                db.log_event("config_brand", user=me, origin=self._origin(), ip=self._client_ip(),
                             detail=f"nombre='{brand_name()}' acento='{brand_accent()}'")
                self._json({"ok": True, "name": brand_name(), "logo": brand_logo(), "accent": brand_accent()})
        elif path == "/admin/users/add":
            body = self._read_body().decode("utf-8", "replace")
            d = parse_qs(body)
            me = (self._current_user() or (None,))[0]
            uname = safe_username(d.get("username", [""])[0])
            scope = "admin" if d.get("scope", ["member"])[0] == "admin" else "member"
            boss = 1 if d.get("boss", [""])[0] == "on" else 0
            invite = d.get("invite", [""])[0] == "on"
            if not uname:
                self._json({"error": "El nombre de usuario es obligatorio"}, 400)
            elif invite:
                # Crear PENDIENTE + enlace de invitación (el usuario pondrá su contraseña).
                if not db.create_pending_user(uname, scope=scope, boss=boss):
                    self._json({"error": "Ese usuario ya existe"}, 409)
                else:
                    token = db.create_invitation(uname, "activate", INVITE_HOURS)
                    url = self._invite_url(token)
                    db.log_event("user_create", user=me, origin=self._origin(),
                                 ip=self._client_ip(), detail=f"{uname} ({scope}, invitación)")
                    self._json({"ok": True, "invite": {"url": url, "qr": self._qr_svg(url),
                                                        "hours": INVITE_HOURS, "username": uname}})
            elif not ALLOW_DIRECT_PW:
                self._json({"error": "La política solo permite crear por invitación"}, 403)
            else:
                pw = d.get("password", [""])[0]
                if len(pw) < MIN_PASSWORD:
                    self._json({"error": f"La contraseña debe tener al menos {MIN_PASSWORD} caracteres"}, 400)
                else:
                    db.create_user(uname, pw, scope=scope, boss=boss)
                    db.log_event("user_create", user=me, origin=self._origin(),
                                 ip=self._client_ip(),
                                 detail=f"{uname} ({scope}{',boss' if boss else ''})")
                    self._json({"ok": True})
        elif path == "/admin/users/del":
            body = self._read_body().decode("utf-8", "replace")
            uname = parse_qs(body).get("username", [""])[0]
            me = (self._current_user() or (None,))[0]
            # No permitir borrarse a uno mismo (evita quedarte sin admin).
            if uname and uname != me:
                db.delete_user(uname)
                db.log_event("user_delete", user=me, origin=self._origin(),
                             ip=self._client_ip(), detail=uname)
            self._send(302, extra=[("Location", "/admin")])
        elif path in ("/admin/dep/add", "/admin/dep/del", "/admin/dep/assign",
                      "/admin/dep/unassign", "/admin/user/boss"):
            body = self._read_body().decode("utf-8", "replace")
            d = parse_qs(body)
            me = (self._current_user() or (None,))[0]
            if path == "/admin/dep/add":
                name = d.get("name", [""])[0].strip()
                if name:
                    slug = db.create_department(name)
                    if slug:
                        os.makedirs(dep_dir(slug), exist_ok=True)
                        db.log_event("dep_create", user=me, origin=self._origin(),
                                     ip=self._client_ip(), detail=f"{name} ({slug})")
            elif path == "/admin/dep/del":
                slug = os.path.basename(d.get("slug", [""])[0])
                if slug:
                    db.delete_department(slug)   # conserva la carpeta y sus archivos (no borra datos)
                    db.log_event("dep_delete", user=me, origin=self._origin(),
                                 ip=self._client_ip(), detail=slug)
            elif path == "/admin/dep/assign":
                db.add_membership(d.get("username", [""])[0],
                                  os.path.basename(d.get("slug", [""])[0]),
                                  d.get("role", ["member"])[0])
            elif path == "/admin/dep/unassign":
                db.remove_membership(d.get("username", [""])[0],
                                     os.path.basename(d.get("slug", [""])[0]))
            elif path == "/admin/user/boss":
                db.set_boss(d.get("username", [""])[0], d.get("boss", [""])[0] == "on")
            self._send(302, extra=[("Location", "/admin")])
        elif path == "/admin/user/rename":
            d = parse_qs(self._read_body().decode("utf-8", "replace"))
            me = (self._current_user() or (None,))[0]
            old = d.get("username", [""])[0]
            new = safe_username(d.get("new", [""])[0])
            if not old or not new:
                self._json({"error": "Nombre de usuario inválido"}, 400)
            elif db.rename_user(old, new):
                db.log_event("user_rename", user=me, origin=self._origin(),
                             ip=self._client_ip(), detail=f"{old} → {new}")
                self._json({"ok": True, "username": new})
            else:
                self._json({"error": "Ese nombre ya existe o el usuario no existe"}, 409)
        elif path == "/admin/user/password":
            d = parse_qs(self._read_body().decode("utf-8", "replace"))
            me = (self._current_user() or (None,))[0]
            uname = d.get("username", [""])[0]
            pw = d.get("password", [""])[0]
            if not ALLOW_DIRECT_PW:
                self._json({"error": "La política solo permite restablecer por enlace"}, 403)
            elif len(pw) < MIN_PASSWORD:
                self._json({"error": f"La contraseña debe tener al menos {MIN_PASSWORD} caracteres"}, 400)
            elif db.set_password(uname, pw):
                db.log_event("user_pwreset", user=me, origin=self._origin(),
                             ip=self._client_ip(), detail=uname)
                self._json({"ok": True})
            else:
                self._json({"error": "Usuario no encontrado"}, 404)
        elif path == "/admin/user/role":
            d = parse_qs(self._read_body().decode("utf-8", "replace"))
            me = (self._current_user() or (None,))[0]
            uname = d.get("username", [""])[0]
            role = d.get("role", ["member"])[0]
            cur = db.get_user(uname)
            if not cur:
                self._json({"error": "Usuario no encontrado"}, 404)
            elif cur["scope"] == "admin" and role != "admin" and db.count_admins() <= 1:
                self._json({"error": "No puedes quitar el rol al último administrador"}, 409)
            else:
                db.set_user_role(uname, role)
                db.log_event("user_role", user=me, origin=self._origin(),
                             ip=self._client_ip(), detail=f"{uname} → {role}")
                self._json({"ok": True})
        elif path in ("/admin/papelera/borrar", "/admin/papelera/restaurar", "/admin/papelera/eliminar"):
            d = parse_qs(self._read_body().decode("utf-8", "replace"))
            me = (self._current_user() or (None,))[0]
            if path == "/admin/papelera/borrar":
                dep = os.path.basename(d.get("dep", [""])[0])
                sub = os.path.basename(d.get("sub", [""])[0]) or None
                name = d.get("file", [""])[0]
                item, err = move_to_trash(dep, sub, name, me)
                if err:
                    self._json({"error": err}, 404)
                else:
                    db.log_event("file_trash", user=me, origin=self._origin(), ip=self._client_ip(),
                                 detail=db.folder_tag(dep, sub) + os.path.basename(name))
                    self._json({"ok": True, "id": item})
            else:
                try:
                    item_id = int(d.get("id", ["0"])[0])
                except ValueError:
                    item_id = 0
                it = db.trash_get(item_id)
                if not it:
                    self._json({"error": "No está en la papelera."}, 404)
                elif path == "/admin/papelera/restaurar":
                    final, err = restore_from_trash(item_id)
                    if err:
                        self._json({"error": err}, 409)
                    else:
                        db.log_event("file_restore", user=me, origin=self._origin(), ip=self._client_ip(),
                                     detail=db.folder_tag(it["dept_slug"], it["sub_slug"]) + final
                                     + ("" if final == it["name"] else f" (antes {it['name']}: ya había uno igual)"))
                        self._json({"ok": True, "name": final})
                else:
                    purge_trash_item(item_id)
                    db.log_event("file_purge", user=me, origin=self._origin(), ip=self._client_ip(),
                                 detail=db.folder_tag(it["dept_slug"], it["sub_slug"]) + it["name"],
                                 bytes=it["size"])
                    self._json({"ok": True})
        elif path == "/admin/config/papelera":
            d = parse_qs(self._read_body().decode("utf-8", "replace"))
            me = (self._current_user() or (None,))[0]
            try:
                dias = int(d.get("days", [""])[0])
            except ValueError:
                dias = -1
            if not 0 <= dias <= 3650:
                self._json({"error": "Pon un número de días entre 0 (nunca se vacía sola) y 3650."}, 400)
            else:
                db.meta_set(TRASH_KEY, str(dias))
                db.log_event("config_trash", user=me, origin=self._origin(), ip=self._client_ip(),
                             detail=f"papelera: {dias} días" if dias else "papelera: nunca se vacía sola")
                self._json({"ok": True, "days": dias})
        elif path == "/admin/user/supervisor":
            d = parse_qs(self._read_body().decode("utf-8", "replace"))
            me = (self._current_user() or (None,))[0]
            uname = d.get("username", [""])[0]
            on = d.get("on", [""])[0] in ("1", "on", "true")
            if not db.set_supervisor(uname, on):
                self._json({"error": "Usuario no encontrado"}, 404)
            else:
                db.log_event("user_supervisor", user=me, origin=self._origin(), ip=self._client_ip(),
                             detail=f"{uname} → {'supervisor' if on else 'sin supervisor'}")
                self._json({"ok": True})
        elif path == "/admin/invite":
            d = parse_qs(self._read_body().decode("utf-8", "replace"))
            me = (self._current_user() or (None,))[0]
            uname = d.get("username", [""])[0]
            purpose = "reset" if d.get("purpose", [""])[0] == "reset" else "activate"
            if not db.get_user(uname):
                self._json({"error": "Usuario no encontrado"}, 404)
            else:
                token = db.create_invitation(uname, purpose, INVITE_HOURS)
                url = self._invite_url(token)
                db.log_event("invite_create", user=me, origin=self._origin(),
                             ip=self._client_ip(), detail=f"{uname} ({purpose})")
                self._json({"ok": True, "url": url, "qr": self._qr_svg(url),
                            "hours": INVITE_HOURS, "username": uname})
        elif path == "/admin/licencia":
            d = parse_qs(self._read_body().decode("utf-8", "replace"))
            text = (d.get("license", [""])[0] or "").strip()
            me = (self._current_user() or (None,))[0]
            if license.parse(text) is None:
                self._send(200, render_license(self._license(),
                    err='<div class="err-msg">La licencia no es válida (firma o formato incorrectos).</div>'))
            else:
                try:
                    with open(os.path.join(DATA_DIR, license.LICENSE_FILENAME), "w",
                              encoding="ascii") as f:
                        f.write(text)
                    state = license_refresh(self.server, force=True)   # recalcula y cachea ya
                    db.log_event("license_install", user=me, origin=self._origin(),
                                 ip=self._client_ip(),
                                 detail=f"{state.get('customer')} · {state.get('type')} · {state.get('expires')}")
                    self._send(200, render_license(state,
                        ok='<div class="ok-msg">Licencia instalada correctamente.</div>'))
                except OSError:
                    self._send(200, render_license(self._license(),
                        err='<div class="err-msg">No se pudo guardar la licencia en el servidor.</div>'))
        elif path == "/api/v1/upload":
            self._handle_api_upload()
        elif path.startswith("/admin/service/"):
            d = parse_qs(self._read_body().decode("utf-8", "replace"))
            me = (self._current_user() or (None,))[0]
            nombre = d.get("name", [""])[0].strip()
            if path == "/admin/service/add":
                if db.create_service_account(nombre):
                    db.log_event("service_add", user=me, origin=self._origin(),
                                 ip=self._client_ip(), detail=nombre)
                    self._json({"ok": True})
                else:
                    self._json({"error": "Nombre no válido o ya existe"}, 400)
            elif not db.is_service_account(nombre):
                # Todas las demás acciones exigen que el destino SEA una cuenta de servicio: así
                # esta ruta nunca puede usarse para tocar la cuenta de una persona.
                self._json({"error": "No es una cuenta de servicio"}, 404)
            elif path == "/admin/service/del":
                db.delete_user(nombre)      # sus claves caen con ella (FOREIGN KEY ON DELETE CASCADE)
                db.log_event("service_del", user=me, origin=self._origin(),
                             ip=self._client_ip(), detail=nombre)
                self._json({"ok": True})
            elif path == "/admin/service/key":
                tok = db.create_device_token(nombre, d.get("label", [""])[0] or "clave")
                if tok:
                    db.log_event("service_key_new", user=me, origin=self._origin(),
                                 ip=self._client_ip(), detail=nombre)
                    self._json({"ok": True, "token": tok})     # se muestra UNA vez
                else:
                    self._json({"error": "No se pudo crear la clave"}, 400)
            elif path == "/admin/service/revoke":
                try:
                    kid = int(d.get("id", ["0"])[0])
                except ValueError:
                    kid = 0
                if db.revoke_device_token(nombre, kid):
                    db.log_event("service_key_revoke", user=me, origin=self._origin(),
                                 ip=self._client_ip(), detail=f"{nombre} id={kid}")
                    self._json({"ok": True})
                else:
                    self._json({"error": "Clave no encontrada o ya revocada"}, 404)
            else:   # /admin/service/remote
                permitir = d.get("allow", [""])[0] == "1"
                db.set_remote_access(nombre, permitir)
                db.log_event("service_remote", user=me, origin=self._origin(),
                             ip=self._client_ip(),
                             detail=f"{nombre} -> {'remoto permitido' if permitir else 'solo LAN'}")
                self._json({"ok": True})
        elif path in ("/admin/sub/add", "/admin/sub/del", "/admin/sub/access"):
            d = parse_qs(self._read_body().decode("utf-8", "replace"))
            me = (self._current_user() or (None,))[0]
            dep = os.path.basename(d.get("dep", [""])[0])
            if dep not in {x["slug"] for x in db.list_departments()}:
                self._json({"error": "Departamento no encontrado"}, 404)
            elif path == "/admin/sub/add":
                slug = db.create_subfolder(dep, d.get("name", [""])[0])
                if not slug:
                    self._json({"error": "Nombre de subcarpeta no válido"}, 400)
                else:
                    try:
                        os.makedirs(sub_dir(dep, slug), exist_ok=True)
                    except OSError:
                        pass
                    db.log_event("subfolder_add", user=me, origin=self._origin(),
                                 ip=self._client_ip(), detail=f"{dep}/{slug}")
                    self._json({"ok": True, "slug": slug})
            elif path == "/admin/sub/del":
                sub = os.path.basename(d.get("sub", [""])[0])
                # Igual que con los departamentos: se quita del sistema, pero la carpeta y los
                # archivos SE CONSERVAN en disco. Nunca se borran datos del cliente.
                if db.delete_subfolder(dep, sub):
                    db.log_event("subfolder_del", user=me, origin=self._origin(),
                                 ip=self._client_ip(), detail=f"{dep}/{sub} (archivos conservados)")
                    self._json({"ok": True})
                else:
                    self._json({"error": "Subcarpeta no encontrada"}, 404)
            else:   # /admin/sub/access
                sub = os.path.basename(d.get("sub", [""])[0])
                user = d.get("user", [""])[0].strip()
                role = d.get("role", [""])[0].strip() or None
                if role is not None and role not in db.SUBFOLDER_ROLES:
                    self._json({"error": "Rol no válido"}, 400)
                elif db.set_subfolder_access(user, dep, sub, role):
                    db.log_event("subfolder_access", user=me, origin=self._origin(),
                                 ip=self._client_ip(),
                                 detail=f"{dep}/{sub}: {user} -> {role or 'sin acceso'}")
                    self._json({"ok": True})
                else:
                    self._json({"error": "Usuario o subcarpeta no encontrados"}, 404)
        elif path in ("/admin/sub/link", "/admin/sub/link/revoke"):
            d = parse_qs(self._read_body().decode("utf-8", "replace"))
            me = (self._current_user() or (None,))[0]
            dep = os.path.basename(d.get("dep", [""])[0])
            if dep not in {x["slug"] for x in db.list_departments()}:
                self._json({"error": "Departamento no encontrado"}, 404)
            elif path == "/admin/sub/link":
                sub = os.path.basename(d.get("sub", [""])[0])
                label = d.get("label", [""])[0]
                try:
                    hours = int(d.get("hours", ["24"])[0])
                except ValueError:
                    hours = 24
                one_shot = d.get("one_shot", [""])[0] in ("1", "on", "true")
                token = db.create_buzon_link(dep, sub, label, me, hours=hours, one_shot=one_shot)
                if not token:
                    self._json({"error": "Subcarpeta no encontrada"}, 404)
                else:
                    db.log_event("buzon_link_new", user=me, origin=self._origin(),
                                 ip=self._client_ip(),
                                 detail=(f"{dep}/{sub} · {hours}h · "
                                         + ("1 archivo" if one_shot else "varios")
                                         + (f" · {label.strip()[:40]}" if label.strip() else "")))
                    # El token EN CLARO se devuelve aquí y nunca más (en la BD solo queda su hash).
                    self._json({"ok": True, "url": self._buzon_url(token)})
            else:   # /admin/sub/link/revoke
                try:
                    lid = int(d.get("id", ["0"])[0])
                except ValueError:
                    lid = 0
                if db.revoke_buzon_link(lid):
                    db.log_event("buzon_link_revoke", user=me, origin=self._origin(),
                                 ip=self._client_ip(), detail=f"{dep} · enlace #{lid}")
                    self._json({"ok": True})
                else:
                    self._json({"error": "Enlace no encontrado"}, 404)
        elif path == "/perfil/2fa/iniciar":
            # Genera un secreto NUEVO y lo devuelve (QR + texto). No se guarda hasta que el admin
            # demuestra con un código que su app lo ha leído bien (/perfil/2fa/activar).
            self._read_body()
            me = self._username()
            sec = totp.new_secret()
            uri = totp.uri(sec, me, brand_name())
            self._json({"ok": True, "secret": sec, "qr": self._qr_svg(uri)})
        elif path == "/perfil/2fa/activar":
            d = parse_qs(self._read_body().decode("utf-8", "replace"))
            me = self._username()
            sec = d.get("secret", [""])[0].strip().upper()
            if db.totp_status(me)["enabled"]:
                self._json({"error": "La verificación en dos pasos ya está activada."}, 409)
            elif not totp.valid_secret(sec):
                self._json({"error": "Secreto no válido. Vuelve a empezar."}, 400)
            else:
                counter = totp.verify(sec, d.get("code", [""])[0])
                if counter is None:
                    self._json({"error": "El código no coincide. Comprueba que la hora del móvil es "
                                         "automática y prueba con el código nuevo."}, 400)
                else:
                    codes = db.totp_enable(me, sec, counter)
                    db.log_event("2fa_enabled", user=me, origin=self._origin(), ip=self._client_ip())
                    self._json({"ok": True, "recovery": codes})
        elif path in ("/perfil/2fa/desactivar", "/perfil/2fa/codigos"):
            d = parse_qs(self._read_body().decode("utf-8", "replace"))
            me = self._username()
            if path == "/perfil/2fa/desactivar" and require_2fa_admins() and self._is_admin():
                self._json({"error": "Tu organización exige la verificación en dos pasos a los "
                                     "administradores: no se puede desactivar."}, 409)
            elif not db.totp_check(me, d.get("code", [""])[0]):
                self._json({"error": "Código incorrecto o ya usado."}, 400)
            elif path == "/perfil/2fa/desactivar":
                db.totp_disable(me)
                db.log_event("2fa_disabled", user=me, origin=self._origin(), ip=self._client_ip())
                notify_telegram(f"SEGURIDAD: {me} ha desactivado su verificación en dos pasos.\n"
                                f"Hora: {time.strftime('%H:%M')}")
                self._json({"ok": True})
            else:
                codes = db.totp_regen_recovery(me)
                db.log_event("2fa_recovery_new", user=me, origin=self._origin(), ip=self._client_ip())
                self._json({"ok": True, "recovery": codes})
        elif path == "/admin/user/2fa/reset":
            d = parse_qs(self._read_body().decode("utf-8", "replace"))
            me = (self._current_user() or (None,))[0]
            uname = d.get("username", [""])[0]
            if not db.totp_disable(uname):
                self._json({"error": "Ese usuario no tiene la verificación en dos pasos activada."}, 404)
            else:
                db.log_event("2fa_reset", user=me, origin=self._origin(), ip=self._client_ip(), detail=uname)
                notify_telegram(f"SEGURIDAD: {me} ha quitado la verificación en dos pasos de {uname}.\n"
                                f"Hora: {time.strftime('%H:%M')}")
                self._json({"ok": True})
        elif path == "/admin/config/2fa":
            d = parse_qs(self._read_body().decode("utf-8", "replace"))
            me = (self._current_user() or (None,))[0]
            on = d.get("on", [""])[0] in ("1", "on", "true")
            db.meta_set(TWOFA_POLICY_KEY, "1" if on else "0")
            db.log_event("config_2fa", user=me, origin=self._origin(), ip=self._client_ip(),
                         detail="2FA obligatorio para administradores: " + ("sí" if on else "no"))
            self._json({"ok": True, "on": on})
        elif path in ("/perfil/token/new", "/perfil/token/revoke"):
            d = parse_qs(self._read_body().decode("utf-8", "replace"))
            me = self._username()
            if path == "/perfil/token/new":
                # Un token por equipo. Se devuelve EN CLARO aquí y nunca más: en la BD solo
                # queda su hash, igual que con las contraseñas y las invitaciones.
                tok = db.create_device_token(me, d.get("name", [""])[0] or "Equipo")
                if not tok:
                    self._json({"error": "No se pudo crear el token"}, 400)
                else:
                    db.log_event("devicetoken_new", user=me, origin=self._origin(),
                                 ip=self._client_ip(), detail=d.get("name", [""])[0][:60])
                    self._json({"ok": True, "token": tok})
            else:
                try:
                    tid = int(d.get("id", ["0"])[0])
                except ValueError:
                    tid = 0
                if db.revoke_device_token(me, tid):
                    db.log_event("devicetoken_revoke", user=me, origin=self._origin(),
                                 ip=self._client_ip(), detail=f"id={tid}")
                    self._json({"ok": True})
                else:
                    self._json({"error": "Token no encontrado o ya revocado"}, 404)
        elif path == "/novedades/leidas":
            d = parse_qs(self._read_body().decode("utf-8", "replace"))
            me = self._username() or ""
            # Solo se pueden marcar carpetas que ESTE usuario ve. Si no se filtrara, cualquiera
            # podría escribir marcas de carpetas ajenas: no le enseñaría nada, pero ensuciaría
            # la tabla y sería un permiso que nadie le dio.
            mias = {k for k, _ in self._mis_carpetas()}
            pedidas = [c for c in d.get("carpeta", []) if c]
            claves = sorted(mias) if d.get("todas") else [c for c in pedidas if c in mias]
            if not claves:
                self._json({"error": "No hay novedades que marcar"}, 400)
            else:
                n = db.mark_folders_seen(me, claves)
                db.log_event("news_seen", user=me, origin=self._origin(),
                             ip=self._client_ip(),
                             detail=("todas" if d.get("todas") else ", ".join(claves))[:200])
                self._json({"ok": True, "marcadas": n})
        elif path == "/perfil/solicitar":
            d = parse_qs(self._read_body().decode("utf-8", "replace"))
            me = self._username()
            slug = os.path.basename(d.get("slug", [""])[0])
            if slug not in {x["slug"] for x in db.list_departments()}:
                self._json({"error": "Departamento no encontrado"}, 404)
            elif db.has_permission(me, "dept.view", slug):
                self._json({"error": "Ya tienes acceso a ese departamento"}, 409)
            elif db.create_access_request(me, slug):
                db.log_event("access_request", user=me, origin=self._origin(),
                             ip=self._client_ip(), detail=slug)
                self._json({"ok": True})
            else:
                self._json({"error": "Ya tienes una solicitud pendiente para ese departamento"}, 409)
        elif path == "/admin/request/resolve":
            d = parse_qs(self._read_body().decode("utf-8", "replace"))
            me = (self._current_user() or (None,))[0]
            try:
                rid = int(d.get("id", ["0"])[0])
            except ValueError:
                rid = 0
            approve = d.get("action", [""])[0] == "approve"
            res = db.resolve_access_request(rid, approve, me)
            if res is None:
                self._json({"error": "Solicitud no encontrada o ya resuelta"}, 404)
            else:
                db.log_event("access_" + res[2], user=me, origin=self._origin(),
                             ip=self._client_ip(), detail=f"{res[0]} → {res[1]}")
                self._json({"ok": True})
        else:
            self._send(404, b"No encontrado", "text/plain; charset=utf-8")

    # -------------------------------------------------- logica descarga (departamentos/)
    def _list_files(self, base_dir):
        """Lista los archivos descargables de una carpeta. La carpeta es OBLIGATORIA: antes había
        un valor por defecto (el buzón personal) que, ante un fallo, habría servido otra carpeta."""
        items, _ = self._list_dir(base_dir)
        return items

    def _list_dir(self, base_dir, limit=None, after=None, query=None):
        """Lista ficheros de una carpeta. Oculta los sidecar .sha256 y adjunta el hash.

        `query` (opcional): filtra por subcadena en el nombre, insensible a mayúsculas. El
        filtro se aplica ANTES de paginar, así que la búsqueda y el cursor conviven.

        Devuelve `(items, cursor_siguiente)`. Sin `limit` devuelve la carpeta entera y el cursor es
        None, que es lo que necesitan las pantallas de la web.

        Orden: fecha descendente y, a igualdad, nombre ascendente. El desempate por nombre no es
        cosmético: sin él, dos ficheros con el mismo mtime podrían intercambiarse entre dos
        peticiones y la paginación saltarse uno o repetirlo.

        El hash de cada fichero vive en un sidecar aparte, o sea **una lectura de disco por
        fichero**. Por eso se leen SOLO los de la página que se va a devolver: en una carpeta de
        20.000 ficheros, pedir 500 hace 500 lecturas, no 20.000.
        """
        crudos = []
        q = (query or "").strip().lower()
        try:
            for name in os.listdir(base_dir):
                if name.endswith(SHA_EXT):
                    continue                       # no listar los ficheros de comprobación
                if q and q not in name.lower():
                    continue                       # búsqueda por nombre (subcadena, sin mayúsc.)
                p = os.path.join(base_dir, name)
                try:
                    st = os.stat(p)
                except OSError:
                    continue                       # desapareció entre el listado y el stat
                if os.path.isfile(p):
                    crudos.append((st.st_mtime, name, st.st_size))
        except OSError:
            return [], None

        crudos.sort(key=lambda e: (-e[0], e[1]))

        # Cursor por CLAVE (no por posición): se reanuda en el fichero siguiente al último
        # entregado. Si entretanto se borra algo, no se salta ninguno; si se añade algo más
        # reciente, aparecerá arriba en una consulta nueva, no en mitad de esta.
        if after:
            crudos = [e for e in crudos if (-e[0], e[1]) > after]

        siguiente = None
        if limit is not None and len(crudos) > limit:
            ultimo = crudos[limit - 1]
            siguiente = _cursor_encode(ultimo[0], ultimo[1])
            crudos = crudos[:limit]

        items = [{"name": n, "size": sz, "mtime": mt,
                  "sha256": read_sidecar_hash(os.path.join(base_dir, n))}
                 for mt, n, sz in crudos]
        return items, siguiente

    def _handle_setup(self):
        """Procesa el asistente de primer arranque: crea el administrador e instala la licencia
        opcional. Solo válido si aún no hay usuarios y desde la LAN."""
        if not self._is_lan():
            self._read_body()
            self._send(403, b"Solo desde la red local", "text/plain; charset=utf-8")
            return
        if db.count_users() > 0:                     # anti-carrera: alguien ya configuró
            self._read_body()
            self._send(302, extra=[("Location", "/login")])
            return
        d = parse_qs(self._read_body().decode("utf-8", "replace"))
        user = safe_username(d.get("username", [""])[0])
        pw = d.get("password", [""])[0]
        pw2 = d.get("password2", [""])[0]
        lic_text = (d.get("license", [""])[0] or "").strip()
        if not user:
            self._send(200, render_setup('<div class="err-msg">El nombre de usuario es obligatorio.</div>'))
            return
        if len(pw) < MIN_PASSWORD:
            self._send(200, render_setup(f'<div class="err-msg">La contraseña debe tener al menos {MIN_PASSWORD} caracteres.</div>'))
            return
        if pw != pw2:
            self._send(200, render_setup('<div class="err-msg">Las contraseñas no coinciden.</div>'))
            return
        if lic_text and license.parse(lic_text) is None:
            self._send(200, render_setup('<div class="err-msg">La licencia pegada no es válida. Déjala vacía o pega la correcta.</div>'))
            return
        db.create_user(user, pw, scope="admin")
        self.server.configured = True
        if lic_text:
            try:
                with open(os.path.join(DATA_DIR, license.LICENSE_FILENAME), "w", encoding="ascii") as f:
                    f.write(lic_text)
                license_refresh(self.server, force=True)
            except OSError:
                pass
        db.log_event("setup_done", user=user, origin=self._origin(), ip=self._client_ip(), detail=user)
        self._send(302, extra=[("Location", "/login?welcome=1")])

    def _handle_export(self):
        """Exporta los datos: descarga un backup consistente de la BD (usuarios, permisos, auditoría).
        Disponible SIEMPRE, incluso con licencia caducada: el cliente nunca es rehén de sus datos.
        (Los archivos de departamento están en la carpeta de datos del propio servidor del cliente.)"""
        ts = time.strftime("%Y%m%d-%H%M%S")
        tmp = os.path.join(DATA_DIR, f".export-{ts}.db")
        try:
            db.backup_db(tmp)
            with open(tmp, "rb") as f:
                data = f.read()
        except Exception:
            self._send(500, b"Error al exportar", "text/plain; charset=utf-8")
            return
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass
        me = (self._current_user() or (None,))[0]
        db.log_event("data_export", user=me, origin=self._origin(),
                     ip=self._client_ip(), bytes=len(data))
        self._send(200, data, "application/octet-stream",
                   extra=[("Content-Disposition",
                           f'attachment; filename="hylanlock-export-{ts}.db"')])

    def _handle_api_upload(self):
        """POST /api/v1/upload?folder=<clave>&name=<archivo> — subida en UNA sola petición.

        A diferencia de la web (tres peticiones, pensada para reanudar en un móvil con mala
        cobertura), una integración quiere mandar el fichero y terminar. El cuerpo se escribe
        A DISCO A TROZOS: un ERP puede mandar un fichero de 2 GB y el servidor no debe intentar
        tenerlo en memoria."""
        q = self._query()
        me = self._username() or ""
        dep, sub, base = self._api_folder(q.get("folder", [""])[0])
        crudo = (q.get("name", [""])[0] or "")
        # Mismo saneado que la web (safe_relpath): fuera rutas, caracteres de control y <>:"|?*.
        # Antes solo se quitaba la ruta, y en Linux un nombre con HTML se guardaba tal cual.
        nombre = safe_relpath(os.path.basename(crudo.replace("\\", "/")))[-1] if crudo.strip() else ""

        if not dep:
            self._read_body()
            return self._api_error("bad_request", "Falta 'folder' o no tiene forma válida.", 400)
        if not db.has_permission(me, "files.upload", dep, sub):
            self._read_body()
            return self._api_error("forbidden", "Esta clave no puede subir a esa carpeta.", 403)
        if not nombre or nombre in (".", ".."):
            self._read_body()
            return self._api_error("bad_request", "Falta 'name' o no es un nombre de archivo.", 400)
        # 'name' debe ser un nombre PLANO. Un nombre con separadores se podría sanear en silencio
        # (basename ya impide salir de la carpeta), pero entonces la integración creería haber
        # escrito una ruta y tendría otra cosa. En un contrato de máquina, mejor rechazar y decirlo.
        if crudo != nombre:
            self._read_body()
            return self._api_error("bad_request",
                                   "'name' debe ser un nombre de archivo plano: sin rutas ni separadores, "
                                   "ni los caracteres <>:\"|?* o de control. "
                                   f"Recibido {crudo!r}; usa 'folder' para elegir la carpeta.", 400)
        if nombre.endswith(SHA_EXT):
            self._read_body()
            return self._api_error("bad_request",
                                   f"No se admiten ficheros '{SHA_EXT}': los genera el servidor.", 400)
        _bloq = extension_bloqueada(nombre)
        if _bloq:
            self._read_body()
            db.log_event("upload_blocked", user=me, origin=self._origin(), ip=self._client_ip(),
                         detail=f"[api] {nombre} · .{_bloq} bloqueada")
            return self._api_error("blocked_extension",
                                   f"La extensión .{_bloq} está bloqueada por seguridad. Pide al "
                                   "administrador que la permita si es imprescindible.", 415)

        try:
            total = int(self.headers.get("Content-Length", 0))
        except ValueError:
            total = 0
        if total <= 0:
            self._read_body()
            return self._api_error("bad_request", "Cuerpo vacío o sin Content-Length.", 400)
        if total > API_MAX_UPLOAD:
            self._read_body()
            return self._api_error("too_large",
                                   f"El archivo supera el límite de "
                                   f"{human_size(API_MAX_UPLOAD)} por petición.", 413)

        os.makedirs(base, exist_ok=True)
        os.makedirs(PART_DIR, exist_ok=True)
        parcial = os.path.join(PART_DIR, f"api-{secrets.token_hex(8)}.part")
        h = hashlib.sha256()
        leidos = 0
        try:
            with open(parcial, "wb") as f:
                while leidos < total:
                    trozo = self.rfile.read(min(CHUNK_READ, total - leidos))
                    if not trozo:
                        break
                    f.write(trozo)
                    h.update(trozo)
                    leidos += len(trozo)
        except OSError as e:
            self._borra(parcial)
            return self._api_error("io_error", f"No se pudo guardar: {e}", 500)
        if leidos != total:
            self._borra(parcial)
            return self._api_error("incomplete",
                                   "La conexión se cortó antes de recibir el archivo entero.", 400)

        digest = h.hexdigest()
        # Verificación extremo a extremo: si el cliente dice qué hash espera y no cuadra, no se
        # guarda NADA. Es la misma garantía que ya da la web.
        esperado = (self.headers.get("X-SHA256", "") or "").strip().lower()
        if esperado and esperado != digest:
            self._borra(parcial)
            db.log_event("upload_bad_hash", user=me, origin=self._origin(), ip=self._client_ip(),
                         detail=f"[api] {nombre} esperado={esperado[:12]} real={digest[:12]}")
            return self._api_error("hash_mismatch",
                                   f"El SHA-256 no coincide (esperado {esperado[:12]}…, "
                                   f"recibido {digest[:12]}…). No se ha guardado nada.", 422)

        dest = unique_path(base, nombre)
        try:
            os.replace(parcial, dest)          # atómico: o está entero o no está
        except OSError as e:
            self._borra(parcial)
            return self._api_error("io_error", f"No se pudo guardar: {e}", 500)
        write_sidecar_hash(dest, digest)

        lugar = f"{dep}/{sub}" if sub else dep
        db.log_event("upload_sub" if sub else "upload_dep", user=me, origin=self._origin(),
                     ip=self._client_ip(),
                     detail=(db.folder_tag(dep, sub) + os.path.basename(dest)
                             + f" · sha256:{digest[:12]}… · vía API"), bytes=leidos)
        notify_telegram(f"Subida vía API\nIntegración: {me}\n"
                        f"Archivo: {os.path.basename(dest)}\nPeso: {human_size(leidos)}\n"
                        f"Carpeta: {lugar}\nHora: {time.strftime('%H:%M')}")
        self._send(201, json.dumps({"name": os.path.basename(dest), "folder": lugar,
                                    "size": leidos, "sha256": digest}).encode("utf-8"),
                   "application/json; charset=utf-8")

    @staticmethod
    def _borra(ruta):
        try:
            os.remove(ruta)
        except OSError:
            pass

    def _handle_download(self, base_dir, lugar="", api=False):
        """Envia un archivo de una carpeta con soporte de rangos (descarga reanudable).
        'lugar' es la etiqueta de la carpeta para la auditoría (p. ej. 'ventas/ana-privado'):
        en una carpeta privada, saber DE DÓNDE salió el archivo es justo lo que importa.
        'api' hace que los errores salgan en el formato JSON uniforme del contrato público."""
        q = self._query()
        raw = q.get("file", [""])[0]
        # Seguridad: solo el nombre de archivo, nunca rutas ni traversal.
        name = os.path.basename((raw or "").replace("\\", "/"))
        path = os.path.join(base_dir, name)
        # Confirmar que el path resuelto sigue DENTRO de la carpeta.
        real_dir = os.path.realpath(base_dir)
        real_path = os.path.realpath(path)
        if (not name or not os.path.isfile(path)
                or os.path.commonpath([real_dir, real_path]) != real_dir):
            if api:
                self._api_error("not_found", "No existe ese archivo en esa carpeta.", 404)
            else:
                self._send(404, b"No encontrado", "text/plain; charset=utf-8")
            return

        filesize = os.path.getsize(path)
        start, end, status = 0, filesize - 1, 200
        rng = self.headers.get("Range", "")
        if rng.startswith("bytes="):
            try:
                spec = rng.split("=", 1)[1].split(",")[0].strip()
                s, _, e = spec.partition("-")
                if s == "":                       # sufijo: ultimos N bytes
                    start = max(0, filesize - int(e))
                    end = filesize - 1
                else:
                    start = int(s)
                    end = int(e) if e else filesize - 1
                if start > end or start >= filesize:
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{filesize}")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                end = min(end, filesize - 1)
                status = 206
            except (ValueError, IndexError):
                start, end, status = 0, filesize - 1, 200

        length = end - start + 1
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(length))
        self.send_header("Accept-Ranges", "bytes")
        # filename* (RFC 5987) para soportar tildes/unicode sin romper la cabecera.
        self.send_header("Content-Disposition",
                         "attachment; filename*=UTF-8''" + quote(name))
        # Integridad: SHA-256 del archivo (para que el receptor compruebe que llegó íntegro).
        _dg = read_sidecar_hash(path)
        if _dg:
            self.send_header("X-Content-SHA256", _dg)
        if status == 206:
            self.send_header("Content-Range", f"bytes {start}-{end}/{filesize}")
        self.end_headers()

        # Registrar la descarga (solo al inicio, para no spamear con cada rango).
        if status == 200 or start == 0:
            who = (self._current_user() or (None,))[0]
            db.log_event("download", user=who, origin=self._origin(),
                         ip=self._client_ip(),
                         detail=(f"[{lugar}] {name}" if lugar else name), bytes=filesize)
            notify_telegram(
                f"Descarga ({_origin_label(self._origin())})\n"
                f"Usuario: {who or '—'}\n"
                f"Archivo: {name}\n"
                f"Peso: {human_size(filesize)}\n"
                f"Carpeta: {lugar or 'sin especificar'}\n"
                f"Hora: {time.strftime('%H:%M')}")

        try:
            with open(path, "rb") as f:
                f.seek(start)
                remaining = length
                while remaining > 0:
                    chunk = f.read(min(CHUNK_READ, remaining))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass  # el cliente corto la descarga; normal

    def _handle_chunk(self):
        purge_old_parts_if_due()      # barre trozos abandonados (ver purge_old_parts_if_due)
        uid = safe_id(self.headers.get("X-Upload-Id", ""))
        if not uid:
            self._send(400, b"id invalido", "text/plain; charset=utf-8")
            self._read_body()
            return
        try:
            offset = int(self.headers.get("X-Offset", "0"))
        except ValueError:
            offset = -1
        length = int(self.headers.get("Content-Length", 0))
        part = os.path.join(PART_DIR, uid + ".part")

        with id_lock(uid):
            current = os.path.getsize(part) if os.path.exists(part) else 0
            if offset != current:
                # El cliente va desincronizado: le decimos por donde vamos.
                self._read_body()  # descartar el cuerpo
                self._send(409, json.dumps({"received": current}).encode("utf-8"),
                           "application/json; charset=utf-8")
                return
            # Tope de trozos incompletos (H1): frena el pico rápido que la purga por edad no cubre.
            if INCOMPLETE_MAX_BYTES and incompletos_total_bytes() + length > INCOMPLETE_MAX_BYTES:
                self._read_body()  # descartar el cuerpo entrante
                self._send(507, json.dumps({"error": "almacenamiento temporal lleno; reintenta mas tarde"}).encode("utf-8"),
                           "application/json; charset=utf-8")
                return
            try:
                written = 0
                with open(part, "ab") as f:
                    remaining = length
                    while remaining > 0:
                        chunk = self.rfile.read(min(CHUNK_READ, remaining))
                        if not chunk:
                            break
                        f.write(chunk)
                        written += len(chunk)
                        remaining -= len(chunk)
                new_size = current + written
            except Exception as e:
                self._send(500, str(e).encode("utf-8"), "text/plain; charset=utf-8")
                return

        self._send(200, json.dumps({"received": new_size}).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _handle_buzon_drop(self, path):
        """Rutas PÚBLICAS de un enlace de buzón: POST /b/<token>/chunk y /b/<token>/complete. Van
        FUERA de _enforce (sin login): la seguridad es LAN + licencia + token válido + rate-limit +
        bloqueo de extensiones + tope de temporales. Quien deja solo SUELTA, nunca ve el contenido."""
        parts = path.split("/")                    # ['', 'b', '<token>', 'chunk'|'complete']
        token = parts[2] if len(parts) > 3 else ""
        action = parts[3] if len(parts) > 3 else ""
        if not self._is_lan():
            self._read_body()
            self._send(403, b"Solo desde la red local", "text/plain; charset=utf-8")
            return
        if not self._license_ok():
            self._read_body()
            self._send(403, b"Servicio no disponible", "text/plain; charset=utf-8")
            return
        link = db.peek_buzon_link(token)
        if not link:
            self._read_body()
            self._send(403, b"Enlace de buzon no valido o revocado", "text/plain; charset=utf-8")
            return
        if action == "chunk":
            # Reutiliza el acumulador de trozos: no conoce el destino, solo junta bytes en un .part.
            self._handle_chunk()
            return
        if action == "complete":
            ok, _n = buzon_rate_ok(self._client_ip())
            if not ok:
                self._read_body()
                self._send(429, b"Demasiadas entregas; espera un momento.", "text/plain; charset=utf-8")
                return
            self._buzon_complete(link)
            return
        self._read_body()
        self._send(404, b"", "text/plain; charset=utf-8")

    def _buzon_complete(self, link):
        """Finaliza una entrega por enlace: mueve el .part a la subcarpeta del token, bloquea
        extensiones, calcula SHA-256 y lo registra en auditoría (con el nombre si lo pusieron)."""
        q = self._query()
        uid = safe_id(q.get("id", [""])[0])
        dep, sub = link["dept_slug"], link["sub_slug"]
        base = sub_dir(dep, sub)
        raw_name = self.headers.get("X-Filename", "")
        filename = unquote(raw_name) if raw_name else "archivo"
        dropper = (self.headers.get("X-Dropper", "") or "").strip()
        dropper = unquote(dropper)[:60] if dropper else ""
        part = os.path.join(PART_DIR, uid + ".part") if uid else ""
        self._read_body()
        try:
            os.makedirs(base, exist_ok=True)
        except OSError:
            pass
        if not uid or not os.path.exists(part):
            self._send(400, b"No hay datos que finalizar", "text/plain; charset=utf-8")
            return
        rel = safe_relpath(filename)
        _bloq = extension_bloqueada(rel[-1])
        if _bloq:
            self._borra(part)
            db.log_event("upload_blocked", user="enlace de buzon", origin=self._origin(),
                         ip=self._client_ip(), detail=f"{rel[-1]} · .{_bloq} bloqueada")
            self._send(415, f"La extensión .{_bloq} está bloqueada por seguridad."
                       .encode("utf-8"), "text/plain; charset=utf-8")
            return
        subdir = os.path.join(base, *rel[:-1])
        os.makedirs(subdir, exist_ok=True)
        dest = unique_path(subdir, rel[-1])
        try:
            os.replace(part, dest)
        except OSError as e:
            self._send(500, str(e).encode("utf-8"), "text/plain; charset=utf-8")
            return
        size = os.path.getsize(dest)
        digest = sha256_file(dest)
        write_sidecar_hash(dest, digest)
        quien = f"enlace: {dropper}" if dropper else "enlace de buzón"
        marca = db.folder_tag(dep, sub)
        db.log_event("upload_sub", user=quien, origin=self._origin(), ip=self._client_ip(),
                     detail=(marca + os.path.basename(dest) + f" · sha256:{digest[:12]}…"), bytes=size)
        notify_telegram(f"Archivo dejado por enlace en {dep}/{sub}: {os.path.basename(dest)}"
                        + (f" (por {dropper})" if dropper else ""))
        # De un solo archivo: el enlace se cierra solo tras esta entrega (además de su caducidad).
        if link.get("one_shot"):
            db.revoke_buzon_link(link["id"])
        self._json({"ok": True})

    def _handle_complete(self):
        q = self._query()
        uid = safe_id(q.get("id", [""])[0])
        # Toda subida es SOBRE un departamento (zone=dep&dep=<slug>): SOLO LAN + acceso al depto.
        zone = q.get("zone", [""])[0]
        dep = os.path.basename(q.get("dep", [""])[0])
        raw_name = self.headers.get("X-Filename", "")
        filename = unquote(raw_name) if raw_name else "archivo"
        part = os.path.join(PART_DIR, uid + ".part") if uid else ""

        # Destino: departamento (zone=dep) o subcarpeta suya (zone=sub&sub=<slug>). En ambos
        # casos hace falta 'files.upload' SOBRE ese destino concreto — para una subcarpeta eso
        # significa una concesión explícita (o ser jefe/dirección/admin), nunca por ser del depto.
        sub = os.path.basename(q.get("sub", [""])[0])
        if zone == "sub":
            ok = bool(sub) and self._is_lan() and self._has("files.upload", dep, sub)
            base = sub_dir(dep, sub)
        elif zone == "dep":
            ok = self._can_dep(dep, "files.upload")
            base = dep_dir(dep)
        else:
            ok, base = False, ""
        if not ok or not base:
            self._read_body()
            self._send(403, b"Sin permiso para subir a esa carpeta", "text/plain; charset=utf-8")
            return
        self._read_body()
        try:
            os.makedirs(base, exist_ok=True)
        except OSError:
            pass

        if not uid or not os.path.exists(part):
            self._send(400, b"No hay datos que finalizar", "text/plain; charset=utf-8")
            return
        rel = safe_relpath(filename)                      # ["carpeta","sub","archivo.rom"]
        _bloq = extension_bloqueada(rel[-1])
        if _bloq:
            self._borra(part)
            db.log_event("upload_blocked", user=(self._current_user() or (None,))[0],
                         origin=self._origin(), ip=self._client_ip(),
                         detail=f"{rel[-1]} · .{_bloq} bloqueada")
            self._send(415, f"La extensión .{_bloq} está bloqueada por seguridad."
                       .encode("utf-8"), "text/plain; charset=utf-8")
            return
        subdir = os.path.join(base, *rel[:-1])
        os.makedirs(subdir, exist_ok=True)
        dest = unique_path(subdir, rel[-1])
        try:
            os.replace(part, dest)  # mismo disco -> instantaneo, sin copiar
        except OSError as e:
            self._send(500, str(e).encode("utf-8"), "text/plain; charset=utf-8")
            return
        size = os.path.getsize(dest)

        # Integridad: SHA-256 del archivo ya guardado (robusto aun con reanudaciones).
        digest = sha256_file(dest)
        # Verificación extremo a extremo (opcional): si el cliente manda el hash esperado
        # y NO coincide, se descarta el archivo (llegó corrupto o manipulado).
        expected = (self.headers.get("X-SHA256", "") or "").strip().lower()
        if expected and expected != digest:
            try:
                os.remove(dest)
            except OSError:
                pass
            db.log_event("upload_bad_hash", user=(self._current_user() or (None,))[0],
                         origin=self._origin(), ip=self._client_ip(),
                         detail=f"{os.path.basename(dest)} esperado={expected[:12]} real={digest[:12]}")
            self._send(422, json.dumps({"error": "hash_mismatch",
                                        "expected": expected, "sha256": digest}).encode("utf-8"),
                       "application/json; charset=utf-8")
            return
        write_sidecar_hash(dest, digest)   # fichero .sha256 para que el receptor verifique

        who = (self._current_user() or (None,))[0]
        # La auditoría debe decir EXACTAMENTE dónde cayó el archivo: en un buzón de entrega es
        # justo lo que el dueño necesita para saber quién le dejó qué.
        # 'marca' sale de db.folder_tag() a propósito: es la MISMA función que usan las novedades
        # para encontrar estos eventos. Un formato, un solo sitio.
        # Solo hay dos destinos posibles: cualquier otro 'zone' ya se rechazó con 403 más arriba.
        if zone == "sub":
            evt, lugar, marca = "upload_sub", f"{dep} / {sub}", db.folder_tag(dep, sub)
        else:
            evt, lugar, marca = "upload_dep", f"departamento {dep}", db.folder_tag(dep)
        db.log_event(evt, user=who, origin=self._origin(), ip=self._client_ip(),
                     detail=(marca + os.path.basename(dest)
                             + f" · sha256:{digest[:12]}…"), bytes=size)
        notify_telegram(
            f"Subida ({_origin_label(self._origin())})\n"
            f"Usuario: {who or '—'}\n"
            f"Archivo: {os.path.basename(dest)}\n"
            f"Peso: {human_size(size)}\n"
            f"Zona: {lugar}\n"
            f"Hora: {time.strftime('%H:%M')}")
        print(f"  \033[32mGuardado\033[0m   {os.path.basename(dest)}  "
              f"({human_size(size)})", flush=True)

        self._send(200, json.dumps({"name": os.path.basename(dest), "sha256": digest}).encode("utf-8"),
                   "application/json; charset=utf-8")


def _ancho_columnas(texto):
    """Ancho del texto en COLUMNAS de terminal, no en caracteres: los emoji y los signos anchos
    ocupan dos. Sin esto, el marco del banner se descuadra en cuanto hay un emoji."""
    import unicodedata
    n = 0
    for ch in texto:
        # Los caracteres invisibles (selectores de variación como el de , uniones de emoji,
        # tildes combinantes) no ocupan sitio: si se cuentan, el marco sale ancho de más.
        if unicodedata.category(ch) in ("Mn", "Me", "Cf"):
            continue
        n += 2 if (unicodedata.east_asian_width(ch) in ("W", "F") or ord(ch) >= 0x1F300) else 1
    return n


def print_banner(url):
    """Banner de arranque. Pensado para el LOG de un servidor (docker compose logs), no para una
    consola personal: sin QR (volcaba un bloque gigante en cada arranque) y sin instrucciones de
    móvil. Solo lo que un administrador necesita ver al levantar el servicio."""
    C, R, D, G = "\033[36m", "\033[0m", "\033[2m", "\033[32m"
    # La marca también manda aquí: si la empresa renombra el producto (marca blanca), su
    # informático no debe encontrarse el nombre del proveedor en `docker compose logs`.
    titulo = f"{BRAND_LOGO}  {BRAND_NAME.upper()}  ·  transferencia segura"
    # La caja se ajusta al texto en vez de tener un ancho fijo: un emoji ocupa DOS columnas y
    # una marca larga se salía del marco. Así encaja con cualquier nombre y cualquier logo.
    ancho = _ancho_columnas(titulo) + 6
    print()
    print(f"  {C}╔{'═' * ancho}╗{R}")
    print(f"  {C}║{R}   {BRAND_LOGO}  {G}{BRAND_NAME.upper()}{R}  ·  transferencia segura   {C}║{R}")
    print(f"  {C}╚{'═' * ancho}╝{R}")
    print()
    if BIND == "127.0.0.1":
        # Atado al bucle local: se está detrás de un proxy (perfil HTTPS). Anunciar la IP de la
        # LAN sería mentir — por ahí ya no se llega.
        print(f"  Escuchando solo en {G}127.0.0.1:{PORT}{R} {D}(tras el proxy inverso){R}")
        print(f"  {D}Los usuarios entran por el nombre HTTPS que hayas puesto en el Caddyfile.{R}")
    else:
        print(f"  Servicio disponible en:  {G}{url}{R}")
    print(f"  {D}Organización: {ORG_NAME}{R}")
    print(f"  {D}Acceso restringido a la red local: {', '.join(LAN_CIDRS)}{R}")
    if lan_cidrs_publicas():
        print(f"  [31m[AVISO] HYLANLOCK_LAN_CIDR incluye IPs de INTERNET ({', '.join(lan_cidrs_publicas())}): "
              f"internet contaría como red local. Acótalo a tus subredes privadas.{R}")
    try:
        _bext = blocked_ext_set()
    except Exception:
        _bext = BLOCKED_EXT
    if _bext:
        print(f"  {D}Extensiones bloqueadas al subir: {len(_bext)} "
              f"(.{', .'.join(sorted(_bext))}){R}")
    else:
        print(f"  {D}Bloqueo de extensiones: DESACTIVADO{R}")
    print(f"  {D}Datos y base de datos en: {DATA_DIR}{R}")
    print(f"  {D}Gestión de usuarios: panel web /admin  ·  CLI: python3 db.py user list{R}")
    print(flush=True)


def main():
    enable_ansi_colors()
    os.makedirs(PART_DIR, exist_ok=True)
    os.makedirs(DEPTS_DIR, exist_ok=True)
    purge_old_parts()
    globals()["_last_purge"] = time.time()
    db.init_db()      # base de datos (crea tablas events, users, departments, memberships)
    for _d in db.list_departments():          # asegurar la carpeta de cada departamento
        os.makedirs(dep_dir(_d["slug"]), exist_ok=True)

    # Sembrar el admin la 1ª vez (si se define HYLANLOCK_ADMIN_PASSWORD). Login = MULTIUSUARIO.
    if db.count_users() == 0 and PASSWORD:
        db.create_user(ADMIN_USER, PASSWORD, scope="admin")
        print(f"  [init] cuenta admin creada: usuario '{ADMIN_USER}'", flush=True)

    ip = get_local_ip()
    scheme = "https" if TLS_ON else "http"
    url = f"{scheme}://{ip}:{PORT}"

    server = ThreadingHTTPServer((BIND, PORT), Handler)
    # HTTPS directo (sin proxy): si hay cert + clave, se envuelve el socket de escucha en TLS. Es la
    # vía simple para quitar el "No es seguro" sin montar Caddy; Caddy sigue siendo la opción robusta
    # para alta carga (aquí el handshake ocurre en el hilo de accept).
    if TLS_ON:
        import ssl
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=TLS_CERT, keyfile=TLS_KEY)
            server.socket = ctx.wrap_socket(server.socket, server_side=True)
        except (OSError, ssl.SSLError, ValueError) as e:
            print(f"  [TLS] no pude cargar el certificado/clave: {e}", flush=True)
            print("  [TLS] revisa HYLANLOCK_TLS_CERT y HYLANLOCK_TLS_KEY. Arranque cancelado.", flush=True)
            raise SystemExit(1)
    server.url = url
    # Token de sesión PERSISTENTE: se guarda en disco para que los reinicios del
    # servicio NO cierren la sesión de los usuarios (cookie válida 30 días).
    token_file = os.path.join(DATA_DIR, ".session_secret")
    tok = ""
    try:
        with open(token_file) as f:
            tok = f.read().strip()
    except OSError:
        pass
    if not tok:
        tok = secrets.token_hex(32)
        try:
            with open(token_file, "w") as f:
                f.write(tok)
            os.chmod(token_file, 0o600)
        except OSError:
            pass
    server.session_token = tok          # secreto persistente para firmar las cookies (HMAC)
    server.token_file = token_file

    # Estado de licencia inicial (verificación Ed25519 cara -> se hace aquí y se cachea).
    _lic = license_refresh(server, force=True)
    _lic_msg = {license.VALID: f"licencia activa ({_lic.get('customer')}, "
                               f"{_lic.get('days_left')} día(s) restantes)",
                license.EXPIRED: "LICENCIA CADUCADA — servicio bloqueado (los datos se conservan)",
                license.INVALID: "licencia NO VÁLIDA — servicio bloqueado",
                license.MISSING: "SIN licencia — servicio bloqueado (instala una en /admin/licencia)"}
    print(f"  Licencia: {_lic_msg.get(_lic['status'], _lic['status'])}", flush=True)

    # AD/LDAP activado pero sin la librería = el directorio NUNCA responderá y todos los logins
    # de dominio caerán a local en silencio. Sin este aviso, el administrador cree tener AD
    # funcionando y solo ve que "los usuarios del dominio no entran", sin ninguna pista.
    if LDAP_ENABLED and not ldap_auth.LDAP_AVAILABLE:
        print("  \033[33m AD/LDAP está ACTIVADO pero falta la librería 'ldap3': el directorio "
              "no se consultará\033[0m", flush=True)
        print("     \033[2mReconstruye la imagen con:  docker compose build --build-arg "
              "WITH_LDAP=1\033[0m", flush=True)
    elif LDAP_ENABLED:
        _ldaps = LDAP_CONFIG.get("uri", "").lower().startswith("ldaps")
        _ca = bool(LDAP_CONFIG.get("tls_cacert"))
        if not _ldaps:
            print("  \033[33m AD/LDAP en CLARO (ldap://): las contraseñas de dominio viajan sin "
                  "cifrar por la red. Usa ldaps://\033[0m", flush=True)
        elif not _ca:
            print("  \033[33m LDAPS sin CA (HYLANLOCK_LDAP_TLS_CACERT vacío): se cifra, pero NO "
                  "se valida el certificado del DC\033[0m", flush=True)
        else:
            print("  AD/LDAP: LDAPS con validación de certificado", flush=True)

    if TLS_ON:
        print(f"  HTTPS: certificado propio cargado ({os.path.basename(TLS_CERT)}) · se sirve cifrado", flush=True)
    print_banner(url)
    # Solo abrir navegador en un equipo de escritorio (Windows). En el servidor
    # headless no hay GUI, asi que se omite.
    if os.name == "nt":
        threading.Timer(0.8, lambda: webbrowser.open(f"{scheme}://127.0.0.1:{PORT}/")).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Servidor detenido. ¡Hasta luego!")
        server.shutdown()


if __name__ == "__main__":
    main()
