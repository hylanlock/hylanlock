# -*- coding: utf-8 -*-
"""
db.py - Base de datos de auditoría (SQLite) para Hylanlock.

Módulo REUTILIZABLE: el mismo patrón se copiará en futuros proyectos (cada uno con
su propia BD). Solo librería estándar (sqlite3). Registra en una tabla `events` todo
lo que pasa por el servidor con fecha y hora exactas.

Uso como módulo:
    import db
    db.init_db()
    db.log_event("upload", user="nico", origin="remoto", ip="127.0.0.1",
                 detail="foto.jpg", bytes=123456)
    db.recent_events(50)

Uso como CLI (para el script de sync u otros):
    python3 db.py log <tipo> [detalle] [bytes]
    python3 db.py show [N]
"""

import os
import hmac
import hashlib
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta

_PBKDF2_ITER = 200_000
# Salt fijo para el pbkdf2 "en balde" que iguala el tiempo de login cuando el usuario no existe
# (anti-enumeración por temporización, ver verify_user). Su valor no importa: solo el coste.
_DUMMY_SALT = "0" * 32
_TS = "%Y-%m-%d %H:%M:%S"

# Ruta de la BD, dentro de la carpeta de datos configurable (misma que la app).
DATA_DIR = os.environ.get("HYLANLOCK_DATA_DIR",
                          os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
DB_PATH = os.environ.get("HYLANLOCK_DB_PATH", os.path.join(DATA_DIR, "hylanlock.db"))

_lock = threading.Lock()
_conn = None


def _connect():
    global _conn
    if _conn is None:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
        _conn.execute("PRAGMA journal_mode=WAL")      # mejor concurrencia (app multihilo)
        _conn.execute("PRAGMA synchronous=NORMAL")
    return _conn


def init_db():
    """Crea las tablas si no existen. Idempotente."""
    with _lock:
        c = _connect()
        c.executescript("""
        CREATE TABLE IF NOT EXISTS events (
          id     INTEGER PRIMARY KEY AUTOINCREMENT,
          ts     TEXT NOT NULL,     -- fecha/hora local 'YYYY-MM-DD HH:MM:SS'
          type   TEXT NOT NULL,     -- login_ok, login_fail, logout, logout_all,
                                    -- upload, download, sync_pull, brute_block, ...
          user   TEXT,              -- quién (multiusuario); NULL si desconocido
          origin TEXT,              -- 'local' (LAN) o 'remoto' (Funnel)
          ip     TEXT,              -- IP del cliente
          detail TEXT,              -- nombre de archivo, mensaje, etc.
          bytes  INTEGER            -- tamaño cuando aplique
        );
        CREATE INDEX IF NOT EXISTS idx_events_ts   ON events(ts);
        CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);

        CREATE TABLE IF NOT EXISTS users (
          id         INTEGER PRIMARY KEY AUTOINCREMENT,
          username   TEXT UNIQUE NOT NULL,
          pass_hash  TEXT NOT NULL,     -- pbkdf2_hmac sha256 en hex
          salt       TEXT NOT NULL,     -- hex
          scope      TEXT NOT NULL,     -- 'admin' (sysadmin) | 'member' (usuario de empresa)
          boss       INTEGER NOT NULL DEFAULT 0,  -- 1 = jefe/director con acceso a TODOS los deptos
          created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS departments (
          id         INTEGER PRIMARY KEY AUTOINCREMENT,
          name       TEXT NOT NULL,
          slug       TEXT UNIQUE NOT NULL,   -- nombre de carpeta (a-z0-9-)
          created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS memberships (
          user_id       INTEGER NOT NULL,
          department_id INTEGER NOT NULL,
          role          TEXT NOT NULL DEFAULT 'member',  -- 'member' | 'head' (jefe de depto)
          PRIMARY KEY (user_id, department_id),
          FOREIGN KEY (user_id)       REFERENCES users(id)       ON DELETE CASCADE,
          FOREIGN KEY (department_id) REFERENCES departments(id) ON DELETE CASCADE
        );

        -- ---- RBAC (Paso 0.2). Aún NO lo leen los handlers; solo se puebla. ----
        CREATE TABLE IF NOT EXISTS permissions (
          id  INTEGER PRIMARY KEY AUTOINCREMENT,
          key TEXT UNIQUE NOT NULL        -- 'files.upload', 'users.manage', ...
        );
        CREATE TABLE IF NOT EXISTS roles (
          id      INTEGER PRIMARY KEY AUTOINCREMENT,
          name    TEXT UNIQUE NOT NULL,
          builtin INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS role_permissions (
          role_id       INTEGER NOT NULL,
          permission_id INTEGER NOT NULL,
          PRIMARY KEY (role_id, permission_id),
          FOREIGN KEY (role_id)       REFERENCES roles(id)       ON DELETE CASCADE,
          FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS user_roles (
          user_id       INTEGER NOT NULL,
          role_id       INTEGER NOT NULL,
          department_id INTEGER,          -- NULL = global (todos los deptos); si no, acotado a uno
          subfolder_id  INTEGER,          -- si no es NULL, el rol vale SOLO en esa subcarpeta
          FOREIGN KEY (user_id)       REFERENCES users(id)       ON DELETE CASCADE,
          FOREIGN KEY (role_id)       REFERENCES roles(id)       ON DELETE CASCADE,
          FOREIGN KEY (department_id) REFERENCES departments(id) ON DELETE CASCADE,
          FOREIGN KEY (subfolder_id)  REFERENCES subfolders(id)  ON DELETE CASCADE
        );

        -- ---- Subcarpetas dentro de un departamento (un solo nivel, v1) ----
        -- Cada una = carpeta departamentos/<dep-slug>/<slug>/. A diferencia del departamento,
        -- NO se hereda: pertenecer al departamento no da acceso a sus subcarpetas. El acceso es
        -- SIEMPRE explícito (user_roles.subfolder_id), salvo los roles jerárquicos
        -- (head/director/it_admin), que sí bajan. Decisión de Nicolás, 2026-08-25.
        CREATE TABLE IF NOT EXISTS subfolders (
          id            INTEGER PRIMARY KEY AUTOINCREMENT,
          department_id INTEGER NOT NULL,
          name          TEXT NOT NULL,
          slug          TEXT NOT NULL,          -- nombre de carpeta (a-z0-9-)
          created_at    TEXT NOT NULL,
          UNIQUE (department_id, slug),
          FOREIGN KEY (department_id) REFERENCES departments(id) ON DELETE CASCADE
        );

        -- ---- Invitaciones de un solo uso (activar cuenta / restablecer contraseña) ----
        -- El admin nunca conoce la contraseña: genera un enlace temporal y el usuario pone la suya.
        CREATE TABLE IF NOT EXISTS invitations (
          id         INTEGER PRIMARY KEY AUTOINCREMENT,
          token_hash TEXT UNIQUE NOT NULL,          -- SHA-256 del token (NUNCA el token en claro)
          username   TEXT NOT NULL,                 -- usuario destino
          purpose    TEXT NOT NULL DEFAULT 'activate', -- 'activate' | 'reset'
          created_at TEXT NOT NULL,
          expires_at TEXT NOT NULL,
          used_at    TEXT                            -- NULL = sin usar; fecha = usado (un solo uso)
        );
        CREATE INDEX IF NOT EXISTS idx_inv_user ON invitations(username);

        -- ---- Novedades: hasta cuándo ha mirado cada usuario cada carpeta ----
        -- No se duplican notificaciones: las novedades se DERIVAN de la auditoría (tabla events),
        -- que ya registra cada subida con carpeta, autor y hora. Aquí solo se guarda la marca de
        -- lectura. Ventaja: funciona retroactivamente y no hay dos verdades que mantener.
        CREATE TABLE IF NOT EXISTS folder_seen (
          user_id    INTEGER NOT NULL,
          folder_key TEXT NOT NULL,        -- 'ventas' o 'ventas/ana-privado'
          seen_at    TEXT NOT NULL,
          PRIMARY KEY (user_id, folder_key),
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        -- ---- Tokens de dispositivo (agente de sincronización que corre en el PC del usuario) ----
        -- Credencial para software desatendido: NUNCA se guarda el token en claro, solo su
        -- SHA-256 (igual que las invitaciones). Se muestra UNA vez al crearlo. Es revocable por
        -- separado, así que perder un portátil no obliga a cambiar la contraseña del usuario.
        -- Hereda los permisos del usuario dueño: no amplía nada, solo permite actuar sin persona.
        CREATE TABLE IF NOT EXISTS device_tokens (
          id           INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id      INTEGER NOT NULL,
          name         TEXT NOT NULL,          -- 'Portátil de la oficina', para reconocerlo
          token_hash   TEXT UNIQUE NOT NULL,   -- SHA-256 del token (nunca el token)
          created_at   TEXT NOT NULL,
          last_used_at TEXT,
          revoked_at   TEXT,                   -- NULL = activo
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_devtok_user ON device_tokens(user_id);

        -- ---- Metadatos internos clave-valor (p.ej. 'license_seen' para anti-rollback de reloj) ----
        CREATE TABLE IF NOT EXISTS meta (
          key   TEXT PRIMARY KEY,
          value TEXT
        );

        -- ---- Solicitudes de acceso a un departamento (el usuario pide; el admin resuelve) ----
        CREATE TABLE IF NOT EXISTS access_requests (
          id          INTEGER PRIMARY KEY AUTOINCREMENT,
          username    TEXT NOT NULL,
          dept_slug   TEXT NOT NULL,
          status      TEXT NOT NULL DEFAULT 'pending',  -- pending | approved | rejected
          created_at  TEXT NOT NULL,
          resolved_at TEXT,
          resolved_by TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_req_status ON access_requests(status);
        """)
        # Migración idempotente: añadir columnas si la tabla users ya existía sin ellas.
        for _col, _ddl in (
                ("boss",          "ALTER TABLE users ADD COLUMN boss INTEGER NOT NULL DEFAULT 0"),
                ("status",        "ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'"),
                ("token_version", "ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 1"),
                ("source",        "ALTER TABLE users ADD COLUMN source TEXT NOT NULL DEFAULT 'local'"),
                ("subfolder_id",  "ALTER TABLE user_roles ADD COLUMN subfolder_id INTEGER")):
            try:
                c.execute(_ddl)
            except sqlite3.OperationalError:
                pass
        # El índice único DEBE contar la subcarpeta: si no, dar el mismo rol a un usuario en dos
        # subcarpetas del mismo depto chocaría. Se recrea (idempotente y barato).
        c.execute("DROP INDEX IF EXISTS idx_user_roles")
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_user_roles_v2 ON user_roles"
                  "(user_id, role_id, COALESCE(department_id,0), COALESCE(subfolder_id,0))")
        _seed_rbac(c)       # crea permisos y roles builtin (idempotente)
        _migrate_rbac(c)    # traduce scope/boss/memberships -> user_roles (idempotente)
        c.commit()
    try:
        os.chmod(DB_PATH, 0o600)
    except OSError:
        pass


# ------------------------------------------------------------------ Usuarios
def _hash_pw(password, salt_hex):
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                             bytes.fromhex(salt_hex), _PBKDF2_ITER)
    return dk.hex()


def create_user(username, password, scope="member", boss=0):
    """Crea (o actualiza) un usuario con contraseña hasheada.
    scope: 'admin' (sysadmin) | 'member' (usuario de empresa). boss=1 = acceso a todo."""
    salt = secrets.token_hex(16)
    ph = _hash_pw(password, salt)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _lock:
        c = _connect()
        c.execute(
            "INSERT INTO users (username,pass_hash,salt,scope,boss,created_at) "
            "VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(username) DO UPDATE SET pass_hash=excluded.pass_hash, "
            "salt=excluded.salt, scope=excluded.scope, boss=excluded.boss",
            (username, ph, salt, scope, int(boss), ts))
        uid = _user_id(c, username)
        if uid is not None:
            _sync_user_global_roles(c, uid)   # mantiene RBAC en sync (it_admin/director)
        c.commit()


def upsert_ldap_user(username, scope="member", boss=0):
    """Crea o actualiza el usuario ESPEJO de una cuenta de AD/LDAP. No guarda contraseña local usable
    (el login va contra el directorio en cada acceso). source='ldap'.

    Devuelve el id del usuario, o **None si el nombre ya pertenece a una cuenta LOCAL**.

    ⚠️ Esa negativa es la parte importante. Sin ella, un usuario cualquiera del directorio que se
    llame igual que una cuenta local se APODERA de ella: al entrar, su scope/boss sobrescriben los
    de la cuenta local. Probado el 2026-08-26 contra el LDAP de pruebas: un usuario del directorio
    SIN ningún grupo privilegiado, llamado como el administrador local, lo dejó en 'member' —
    la instalación pudo quedarse sin ningún administrador. También reactivaba cuentas locales
    deshabilitadas (status='active').

    Regla: **una cuenta local es dueña de su nombre**. El directorio no la crea, no la modifica y
    no la reactiva. Es lo que sostiene la promesa de que el admin local es el salvavidas."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _lock:
        c = _connect()
        row = c.execute("SELECT source FROM users WHERE username=?", (username,)).fetchone()
        if row is not None and row[0] != "ldap":
            return None                        # el nombre es de una cuenta local: no se toca
        salt = secrets.token_hex(16)
        ph = secrets.token_hex(32)             # nunca valida como contraseña local
        c.execute(
            "INSERT INTO users (username,pass_hash,salt,scope,boss,created_at,source,status) "
            "VALUES (?,?,?,?,?,?, 'ldap', 'active') "
            "ON CONFLICT(username) DO UPDATE SET scope=excluded.scope, boss=excluded.boss, "
            "source='ldap', status='active'",
            (username, ph, salt, scope, int(boss), ts))
        uid = _user_id(c, username)
        if uid is not None:
            _sync_user_global_roles(c, uid)    # traduce scope/boss -> roles globales (it_admin/director)
        c.commit()
        return uid


def sync_ldap_memberships(username, memberships):
    """Reemplaza las membresías de un usuario LDAP por las derivadas de sus grupos de AD.
    'memberships' = lista de (dept_slug, role 'member'|'head'). Departamentos inexistentes se ignoran.
    Un usuario que sale de un grupo PIERDE ese acceso (se revoca en el siguiente login)."""
    with _lock:
        c = _connect()
        uid = _user_id(c, username)
        if uid is None:
            return
        cur = {row[0] for row in c.execute(
            "SELECT d.slug FROM memberships m JOIN departments d ON d.id=m.department_id "
            "WHERE m.user_id=?", (uid,)).fetchall()}
        want = {}
        for slug, role in memberships:
            if _dept_id(c, slug) is not None:
                want[slug] = role if role in ("member", "head") else "member"
        for slug in cur - set(want):               # revocar las que ya no correspondan
            did = _dept_id(c, slug)
            c.execute("DELETE FROM memberships WHERE user_id=? AND department_id=?", (uid, did))
            _sync_membership_role(c, uid, did, None)
        for slug, role in want.items():            # crear/actualizar las deseadas
            did = _dept_id(c, slug)
            c.execute("INSERT INTO memberships (user_id,department_id,role) VALUES (?,?,?) "
                      "ON CONFLICT(user_id,department_id) DO UPDATE SET role=excluded.role",
                      (uid, did, role))
            _sync_membership_role(c, uid, did, role)
        c.commit()


def get_user(username):
    """Devuelve {id, username, scope, boss, status, token_version} o None."""
    try:
        with _lock:
            c = _connect()
            row = c.execute(
                "SELECT id,username,scope,boss,status,token_version FROM users WHERE username=?",
                (username,)).fetchone()
        if not row:
            return None
        return {"id": row[0], "username": row[1], "scope": row[2], "boss": bool(row[3]),
                "status": row[4], "token_version": row[5]}
    except Exception:
        return None


def set_boss(username, boss):
    with _lock:
        c = _connect()
        c.execute("UPDATE users SET boss=? WHERE username=?", (1 if boss else 0, username))
        uid = _user_id(c, username)
        if uid is not None:
            _sync_user_global_roles(c, uid)   # añade/quita el rol global 'director'
        c.commit()


def set_status(username, status):
    """Activa/desactiva un usuario. 'disabled' invalida sus sesiones al instante (ver _current_user)."""
    with _lock:
        c = _connect()
        c.execute("UPDATE users SET status=? WHERE username=?",
                  (status if status in ("active", "disabled") else "active", username))
        c.commit()


def bump_token_version(username):
    """Sube token_version -> invalida TODAS las sesiones vivas de ese usuario (en todos sus equipos)."""
    with _lock:
        c = _connect()
        c.execute("UPDATE users SET token_version = token_version + 1 WHERE username=?", (username,))
        c.commit()


def set_password(username, password):
    """Restablece la contraseña de un usuario (nuevo salt + hash). Sube token_version para cerrar
    sus sesiones abiertas (buena práctica tras un reset). Devuelve True si el usuario existía."""
    salt = secrets.token_hex(16)
    ph = _hash_pw(password, salt)
    with _lock:
        c = _connect()
        cur = c.execute(
            "UPDATE users SET pass_hash=?, salt=?, token_version=token_version+1 WHERE username=?",
            (ph, salt, username))
        c.commit()
        return cur.rowcount > 0


def rename_user(old, new):
    """Renombra un usuario. Las membresías/roles referencian el id (no el nombre), así que se
    conservan. Devuelve False si 'new' ya existe o 'old' no existe."""
    with _lock:
        c = _connect()
        if _user_id(c, new) is not None:
            return False
        cur = c.execute("UPDATE users SET username=? WHERE username=?", (new, old))
        c.commit()
        return cur.rowcount > 0


def set_user_role(username, role):
    """Cambia el rol GLOBAL de un usuario: 'member' | 'head' (director/jefe global) | 'admin'.
    Sincroniza el RBAC (it_admin/director). No toca las membresías por departamento."""
    role = role if role in ("member", "head", "admin") else "member"
    with _lock:
        c = _connect()
        if role == "admin":
            c.execute("UPDATE users SET scope='admin' WHERE username=?", (username,))
        elif role == "head":
            c.execute("UPDATE users SET scope='member', boss=1 WHERE username=?", (username,))
        else:
            c.execute("UPDATE users SET scope='member', boss=0 WHERE username=?", (username,))
        uid = _user_id(c, username)
        if uid is not None:
            _sync_user_global_roles(c, uid)
        c.commit()


def meta_get(key, default=None):
    """Lee un metadato interno (tabla meta). Devuelve 'default' si no existe."""
    try:
        with _lock:
            c = _connect()
            row = c.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else default
    except Exception:
        return default


def meta_set(key, value):
    """Escribe un metadato interno (tabla meta)."""
    with _lock:
        c = _connect()
        c.execute("INSERT INTO meta (key,value) VALUES (?,?) "
                  "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))
        c.commit()


def count_admins():
    """Nº de administradores (scope='admin'). Para no dejar la instancia sin ningún admin."""
    try:
        with _lock:
            c = _connect()
            return c.execute("SELECT COUNT(*) FROM users WHERE scope='admin'").fetchone()[0]
    except Exception:
        return 0


def create_pending_user(username, scope="member", boss=0):
    """Crea un usuario PENDIENTE (sin contraseña utilizable): un hash aleatorio que no corresponde a
    ninguna contraseña. El usuario fijará la suya al activar la invitación. Devuelve True si se creó
    (False si el nombre ya existía)."""
    salt = secrets.token_hex(16)
    ph = secrets.token_hex(32)      # NO es el hash de ninguna contraseña -> jamás valida
    ts = datetime.now().strftime(_TS)
    with _lock:
        c = _connect()
        if _user_id(c, username) is not None:
            return False
        c.execute(
            "INSERT INTO users (username,pass_hash,salt,scope,boss,created_at,status) "
            "VALUES (?,?,?,?,?,?, 'pending')",
            (username, ph, salt, scope, int(boss), ts))
        uid = _user_id(c, username)
        if uid is not None:
            _sync_user_global_roles(c, uid)
        c.commit()
        return True


# ------------------------------------------------------------ Invitaciones (un solo uso)
def create_invitation(username, purpose="activate", hours=48):
    """Genera un token de un solo uso para 'username'. Guarda SOLO su hash. Anula invitaciones
    previas sin usar de ese usuario. Devuelve el token EN CLARO (no se puede volver a obtener)."""
    token = secrets.token_urlsafe(32)
    th = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = datetime.now()
    exp = now + timedelta(hours=hours)
    with _lock:
        c = _connect()
        c.execute("DELETE FROM invitations WHERE username=? AND used_at IS NULL", (username,))
        c.execute(
            "INSERT INTO invitations (token_hash,username,purpose,created_at,expires_at) "
            "VALUES (?,?,?,?,?)",
            (th, username, purpose if purpose in ("activate", "reset") else "activate",
             now.strftime(_TS), exp.strftime(_TS)))
        c.commit()
    return token


def peek_invitation(token):
    """Valida un token SIN canjearlo. Devuelve {username, purpose} si es válido (existe, sin usar,
    no caducado); None si no."""
    try:
        th = hashlib.sha256((token or "").encode("utf-8")).hexdigest()
        with _lock:
            c = _connect()
            row = c.execute(
                "SELECT username, purpose, expires_at, used_at FROM invitations WHERE token_hash=?",
                (th,)).fetchone()
        if not row:
            return None
        username, purpose, expires_at, used_at = row
        if used_at:
            return None
        if datetime.now() > datetime.strptime(expires_at, _TS):
            return None
        return {"username": username, "purpose": purpose}
    except Exception:
        return None


def redeem_invitation(token, password):
    """Canjea un token: fija la contraseña del usuario, activa la cuenta y marca el token usado.
    Devuelve (True, username) o (False, motivo)."""
    th = hashlib.sha256((token or "").encode("utf-8")).hexdigest()
    now = datetime.now()
    with _lock:
        c = _connect()
        row = c.execute(
            "SELECT id, username, expires_at, used_at FROM invitations WHERE token_hash=?",
            (th,)).fetchone()
        if not row:
            return (False, "Enlace no válido.")
        iid, username, expires_at, used_at = row
        if used_at:
            return (False, "Este enlace ya se usó.")
        try:
            if now > datetime.strptime(expires_at, _TS):
                return (False, "El enlace ha caducado. Pide otro a tu administrador.")
        except ValueError:
            return (False, "Enlace no válido.")
        salt = secrets.token_hex(16)
        ph = _hash_pw(password, salt)
        c.execute(
            "UPDATE users SET pass_hash=?, salt=?, status='active', token_version=token_version+1 "
            "WHERE username=?", (ph, salt, username))
        c.execute("UPDATE invitations SET used_at=? WHERE id=?", (now.strftime(_TS), iid))
        c.commit()
        return (True, username)


def verify_user(username, password):
    """Devuelve el scope si usuario+contraseña son correctos y la cuenta está ACTIVA; si no, None.
    Un usuario 'pending' (aún sin activar) o 'disabled' nunca inicia sesión, aunque acierte el hash."""
    try:
        with _lock:
            c = _connect()
            row = c.execute(
                "SELECT pass_hash,salt,scope,status FROM users WHERE username=?",
                (username,)).fetchone()
        # Anti-enumeración por temporización: si el usuario NO existe, está inactivo, o es una cuenta
        # de servicio (que nunca entra por la web aunque alguien acertara su hash), se gasta IGUAL un
        # pbkdf2 con un salt fijo. Así el tiempo de respuesta no revela si la cuenta existe: sin este
        # gasto, "usuario inexistente" respondía al instante y "usuario real" tras el pbkdf2 (lento).
        if not row or row[3] != "active" or row[2] == "service":
            _hash_pw(password, _DUMMY_SALT)          # coste constante; el resultado se descarta
            return None
        ph, salt, scope, _status = row
        if hmac.compare_digest(ph, _hash_pw(password, salt)):
            return scope
        return None
    except Exception:
        return None


def list_users():
    try:
        with _lock:
            c = _connect()
            rows = c.execute(
                "SELECT username,scope,boss,created_at,status FROM users ORDER BY username").fetchall()
        return [{"username": u, "scope": s, "boss": bool(b), "created_at": t, "status": st}
                for u, s, b, t, st in rows]
    except Exception:
        return []


def delete_user(username):
    with _lock:
        c = _connect()
        c.execute("DELETE FROM users WHERE username=?", (username,))
        c.commit()


def count_users():
    try:
        with _lock:
            c = _connect()
            return c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    except Exception:
        return 0


# ------------------------------------------------------------ Departamentos
def slugify(name):
    """Convierte 'Recursos Humanos' -> 'recursos-humanos' (a-z0-9-)."""
    import unicodedata
    s = unicodedata.normalize("NFKD", name or "").encode("ascii", "ignore").decode()
    s = "".join(ch.lower() if ch.isalnum() else "-" for ch in s)
    while "--" in s:
        s = s.replace("--", "-")
    return s.strip("-")[:40] or "depto"


def create_department(name):
    """Crea un departamento. Devuelve su slug (o None si nombre inválido)."""
    slug = slugify(name)
    if not slug:
        return None
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _lock:
        c = _connect()
        c.execute("INSERT OR IGNORE INTO departments (name,slug,created_at) VALUES (?,?,?)",
                  (name.strip(), slug, ts))
        c.commit()
    return slug


def list_departments():
    try:
        with _lock:
            c = _connect()
            rows = c.execute(
                "SELECT name,slug,created_at FROM departments ORDER BY name").fetchall()
        return [{"name": n, "slug": s, "created_at": t} for n, s, t in rows]
    except Exception:
        return []


def delete_department(slug):
    with _lock:
        c = _connect()
        c.execute("PRAGMA foreign_keys=ON")
        c.execute("DELETE FROM departments WHERE slug=?", (slug,))
        c.commit()


def _dept_id(c, slug):
    r = c.execute("SELECT id FROM departments WHERE slug=?", (slug,)).fetchone()
    return r[0] if r else None


def _user_id(c, username):
    r = c.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    return r[0] if r else None


def add_membership(username, slug, role="member"):
    """Asigna un usuario a un departamento con un rol ('member'|'head')."""
    with _lock:
        c = _connect()
        uid, did = _user_id(c, username), _dept_id(c, slug)
        if uid is None or did is None:
            return False
        rr = role if role in ("member", "head") else "member"
        c.execute(
            "INSERT INTO memberships (user_id,department_id,role) VALUES (?,?,?) "
            "ON CONFLICT(user_id,department_id) DO UPDATE SET role=excluded.role",
            (uid, did, rr))
        _sync_membership_role(c, uid, did, rr)   # employee/head acotado a ese depto
        c.commit()
        return True


def remove_membership(username, slug):
    with _lock:
        c = _connect()
        uid, did = _user_id(c, username), _dept_id(c, slug)
        if uid is None or did is None:
            return
        c.execute("DELETE FROM memberships WHERE user_id=? AND department_id=?", (uid, did))
        _sync_membership_role(c, uid, did, None)   # quita el rol acotado en ese depto
        c.commit()


def user_visible_departments(username):
    """Departamentos que el usuario puede VER según RBAC (permiso 'dept.view'): [{slug,name,role}].
    role para la UI: 'all' (dept.view global), 'head' o 'member' (asignación acotada)."""
    try:
        with _lock:
            c = _connect()
            uid = _user_id(c, username)
            if uid is None:
                return []
            # ¿Tiene dept.view GLOBAL? -> ve todos los departamentos (admin/director).
            # ⚠️ 'subfolder_id IS NULL' es imprescindible: las concesiones de SUBCARPETA también
            # llevan department_id NULL, y sin este filtro se leerían como "global" -> un
            # depositario de una sola subcarpeta vería TODOS los departamentos.
            glob = c.execute(
                "SELECT 1 FROM user_roles ur "
                "JOIN role_permissions rp ON rp.role_id = ur.role_id "
                "JOIN permissions p ON p.id = rp.permission_id "
                "WHERE ur.user_id = ? AND ur.department_id IS NULL AND ur.subfolder_id IS NULL "
                "AND p.key = 'dept.view' LIMIT 1",
                (uid,)).fetchone()
            if glob:
                rows = c.execute("SELECT slug, name FROM departments ORDER BY name").fetchall()
                return [{"slug": s, "name": n, "role": "all"} for s, n in rows]
            # Acotados: deptos donde tiene dept.view, con etiqueta según el rol.
            rows = c.execute(
                "SELECT d.slug, d.name, r.name FROM user_roles ur "
                "JOIN roles r ON r.id = ur.role_id "
                "JOIN role_permissions rp ON rp.role_id = ur.role_id "
                "JOIN permissions p ON p.id = rp.permission_id "
                "JOIN departments d ON d.id = ur.department_id "
                "WHERE ur.user_id = ? AND p.key = 'dept.view' ORDER BY d.name",
                (uid,)).fetchall()
        seen = {}
        for slug, name, rolename in rows:
            lbl = "head" if rolename == "head" else "member"
            if slug not in seen or lbl == "head":
                seen[slug] = {"slug": slug, "name": name, "role": lbl}
        return list(seen.values())
    except Exception:
        return []


def create_access_request(username, dept_slug):
    """El usuario solicita acceso a un departamento. Evita duplicados pendientes. Devuelve
    True si se creó, False si ya había una solicitud pendiente para ese depto."""
    ts = datetime.now().strftime(_TS)
    with _lock:
        c = _connect()
        dup = c.execute(
            "SELECT 1 FROM access_requests WHERE username=? AND dept_slug=? AND status='pending'",
            (username, dept_slug)).fetchone()
        if dup:
            return False
        c.execute("INSERT INTO access_requests (username,dept_slug,status,created_at) "
                  "VALUES (?,?,'pending',?)", (username, dept_slug, ts))
        c.commit()
        return True


def list_access_requests(status="pending"):
    """Solicitudes con el nombre del departamento: [{id, username, dept_slug, dept_name, created_at}]."""
    try:
        with _lock:
            c = _connect()
            rows = c.execute(
                "SELECT r.id, r.username, r.dept_slug, COALESCE(d.name, r.dept_slug), r.created_at "
                "FROM access_requests r LEFT JOIN departments d ON d.slug = r.dept_slug "
                "WHERE r.status = ? ORDER BY r.created_at", (status,)).fetchall()
        return [{"id": i, "username": u, "dept_slug": s, "dept_name": n, "created_at": t}
                for i, u, s, n, t in rows]
    except Exception:
        return []


def user_pending_requests(username):
    """Slugs de departamentos con solicitud PENDIENTE de ese usuario (para marcarlos en el perfil)."""
    try:
        with _lock:
            c = _connect()
            rows = c.execute(
                "SELECT dept_slug FROM access_requests WHERE username=? AND status='pending'",
                (username,)).fetchall()
        return [r[0] for r in rows]
    except Exception:
        return []


def count_pending_requests():
    try:
        with _lock:
            c = _connect()
            return c.execute("SELECT COUNT(*) FROM access_requests WHERE status='pending'").fetchone()[0]
    except Exception:
        return 0


def resolve_access_request(req_id, approve, admin):
    """Resuelve una solicitud pendiente. Si se aprueba, añade la membresía (rol 'member').
    Devuelve (username, dept_slug, 'approved'|'rejected') o None si no existe/ya resuelta."""
    ts = datetime.now().strftime(_TS)
    with _lock:
        c = _connect()
        row = c.execute(
            "SELECT username, dept_slug, status FROM access_requests WHERE id=?", (req_id,)).fetchone()
        if not row or row[2] != "pending":
            return None
        username, slug, _ = row
        c.execute("UPDATE access_requests SET status=?, resolved_at=?, resolved_by=? WHERE id=?",
                  ("approved" if approve else "rejected", ts, admin, req_id))
        c.commit()
    if approve:
        add_membership(username, slug, "member")   # tiene su propio lock -> fuera del bloque anterior
    return (username, slug, "approved" if approve else "rejected")


def department_members(slug):
    """Miembros de un departamento: [{username, role}]."""
    try:
        with _lock:
            c = _connect()
            rows = c.execute(
                "SELECT u.username, m.role FROM memberships m "
                "JOIN users u ON u.id=m.user_id "
                "JOIN departments d ON d.id=m.department_id WHERE d.slug=? ORDER BY u.username",
                (slug,)).fetchall()
        return [{"username": u, "role": r} for u, r in rows]
    except Exception:
        return []


# ------------------------------------------------------------------ RBAC (Paso 0)
# El RBAC es la ÚNICA fuente de autorización de la app (los handlers consultan has_permission).
# 'scope'/'boss'/'memberships' YA NO autorizan nada: son el modelo de alta de usuarios (y la UI de
# admin) que ALIMENTA el RBAC — al crear/modificar usuarios o membresías se sincroniza user_roles
# (ver _sync_user_global_roles / _sync_membership_role). Retirarlos del todo implica rehacer la UI de
# admin para asignar roles directamente: es trabajo futuro (con el rediseño del panel), no limpieza.
# ------------------------------------------------------- Subcarpetas (un nivel, dentro de un depto)
# Roles asignables sobre una subcarpeta. 'folder_owner' = el dueño; 'depositor' = deja sin ver
# (buzón de entrega); 'reader' = ve y descarga sin subir.
SUBFOLDER_ROLES = ("folder_owner", "depositor", "reader")


def create_subfolder(dept_slug, name):
    """Crea una subcarpeta dentro de un departamento. Devuelve su slug, o None si no vale."""
    slug = slugify(name)
    if not slug:
        return None
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _lock:
        c = _connect()
        did = _dept_id(c, dept_slug)
        if did is None:
            return None
        c.execute("INSERT OR IGNORE INTO subfolders (department_id,name,slug,created_at) "
                  "VALUES (?,?,?,?)", (did, name.strip(), slug, ts))
        c.commit()
    return slug


def list_subfolders(dept_slug):
    """Todas las subcarpetas de un departamento (sin filtrar por permiso)."""
    try:
        with _lock:
            c = _connect()
            rows = c.execute(
                "SELECT sf.name, sf.slug, sf.created_at FROM subfolders sf "
                "JOIN departments d ON d.id = sf.department_id "
                "WHERE d.slug = ? ORDER BY sf.name", (dept_slug,)).fetchall()
        return [{"name": n, "slug": s, "created_at": t} for n, s, t in rows]
    except Exception:
        return []


def delete_subfolder(dept_slug, sub_slug):
    """Borra la subcarpeta y sus permisos. CONSERVA la carpeta y los archivos en disco
    (misma regla de oro que los departamentos: nunca se borran datos del cliente)."""
    with _lock:
        c = _connect()
        c.execute("PRAGMA foreign_keys=ON")
        did = _dept_id(c, dept_slug)
        if did is None:
            return False
        c.execute("DELETE FROM subfolders WHERE department_id=? AND slug=?", (did, sub_slug))
        c.commit()
    return True


def _subfolder_id(c, dept_slug, sub_slug):
    r = c.execute("SELECT sf.id FROM subfolders sf JOIN departments d ON d.id = sf.department_id "
                  "WHERE d.slug=? AND sf.slug=?", (dept_slug, sub_slug)).fetchone()
    return r[0] if r else None


def set_subfolder_access(username, dept_slug, sub_slug, role):
    """Da a 'username' un rol sobre una subcarpeta (o se lo quita si role es None).
    Sustituye cualquier rol previo suyo en esa subcarpeta: un usuario, un rol por carpeta."""
    if role is not None and role not in SUBFOLDER_ROLES:
        return False
    with _lock:
        c = _connect()
        uid = _user_id(c, username)
        sid = _subfolder_id(c, dept_slug, sub_slug)
        if uid is None or sid is None:
            return False
        c.execute("DELETE FROM user_roles WHERE user_id=? AND subfolder_id=?", (uid, sid))
        if role:
            r = c.execute("SELECT id FROM roles WHERE name=?", (role,)).fetchone()
            if not r:
                return False
            c.execute("INSERT OR IGNORE INTO user_roles (user_id, role_id, department_id, "
                      "subfolder_id) VALUES (?,?,NULL,?)", (uid, r[0], sid))
        c.commit()
    return True


def subfolder_acl(dept_slug, sub_slug):
    """Quién tiene acceso EXPLÍCITO a una subcarpeta y con qué rol (no incluye la jerarquía)."""
    try:
        with _lock:
            c = _connect()
            sid = _subfolder_id(c, dept_slug, sub_slug)
            if sid is None:
                return []
            rows = c.execute(
                "SELECT u.username, r.name FROM user_roles ur "
                "JOIN users u ON u.id = ur.user_id JOIN roles r ON r.id = ur.role_id "
                "WHERE ur.subfolder_id = ? ORDER BY u.username", (sid,)).fetchall()
        return [{"username": u, "role": r} for u, r in rows]
    except Exception:
        return []


def user_visible_subfolders(username, dept_slug):
    """Subcarpetas de un departamento que este usuario puede ver, con lo que puede hacer en cada
    una. Se calcula con has_permission para que la regla viva en UN solo sitio."""
    out = []
    for sf in list_subfolders(dept_slug):
        if not has_permission(username, "dept.view", dept_slug, sf["slug"]):
            continue
        sf = dict(sf)
        sf["can_list"] = has_permission(username, "files.list", dept_slug, sf["slug"])
        sf["can_upload"] = has_permission(username, "files.upload", dept_slug, sf["slug"])
        sf["can_download"] = has_permission(username, "files.download", dept_slug, sf["slug"])
        out.append(sf)
    return out


def user_accessible_subfolders(username):
    """TODAS las subcarpetas a las que este usuario llega, de cualquier departamento, con el
    nombre del depto para poder mostrarlas en la navegación.

    Hace falta porque un depositario puede tener acceso a una subcarpeta SIN ser miembro del
    departamento: sin esto no tendría ninguna forma de llegar a ella desde la interfaz."""
    out = []
    try:
        with _lock:
            c = _connect()
            rows = c.execute(
                "SELECT d.slug, d.name, sf.slug, sf.name FROM subfolders sf "
                "JOIN departments d ON d.id = sf.department_id "
                "ORDER BY d.name, sf.name").fetchall()
    except Exception:
        return []
    for dslug, dname, sslug, sname in rows:
        if not has_permission(username, "dept.view", dslug, sslug):
            continue
        out.append({
            "dept_slug": dslug, "dept_name": dname, "slug": sslug, "name": sname,
            "can_list":     has_permission(username, "files.list", dslug, sslug),
            "can_upload":   has_permission(username, "files.upload", dslug, sslug),
            "can_download": has_permission(username, "files.download", dslug, sslug),
        })
    return out


# --------------------------------------------------- Tokens de dispositivo (agente de sync)
def _tok_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_device_token(username, name):
    """Crea un token para un equipo del usuario. Devuelve el token EN CLARO una sola vez
    (en la BD solo queda su hash). None si el usuario no existe."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    token = "hyl_" + secrets.token_urlsafe(32)
    with _lock:
        c = _connect()
        uid = _user_id(c, username)
        if uid is None:
            return None
        c.execute("INSERT INTO device_tokens (user_id,name,token_hash,created_at) VALUES (?,?,?,?)",
                  (uid, (name or "Equipo").strip()[:60], _tok_hash(token), ts))
        c.commit()
    return token


def verify_device_token(token):
    """Devuelve (username, scope) del dueño de un token ACTIVO, o None. Anota el último uso.
    Exige además que el usuario siga activo: desactivarlo corta también sus agentes."""
    if not token or not token.startswith("hyl_"):
        return None
    try:
        with _lock:
            c = _connect()
            row = c.execute(
                "SELECT dt.id, u.username, u.scope FROM device_tokens dt "
                "JOIN users u ON u.id = dt.user_id "
                "WHERE dt.token_hash = ? AND dt.revoked_at IS NULL AND u.status = 'active'",
                (_tok_hash(token),)).fetchone()
            if not row:
                return None
            c.execute("UPDATE device_tokens SET last_used_at=? WHERE id=?",
                      (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), row[0]))
            c.commit()
        return (row[1], row[2])
    except Exception:
        return None


def list_device_tokens(username):
    """Tokens del usuario (sin el secreto, que no se puede recuperar)."""
    try:
        with _lock:
            c = _connect()
            rows = c.execute(
                "SELECT dt.id, dt.name, dt.created_at, dt.last_used_at, dt.revoked_at "
                "FROM device_tokens dt JOIN users u ON u.id = dt.user_id "
                "WHERE u.username = ? ORDER BY dt.created_at DESC", (username,)).fetchall()
        return [{"id": i, "name": n, "created_at": c_, "last_used_at": l, "revoked": bool(r)}
                for i, n, c_, l, r in rows]
    except Exception:
        return []


def revoke_device_token(username, token_id):
    """Revoca un token del usuario (solo suyo). Irreversible; el agente deja de funcionar."""
    with _lock:
        c = _connect()
        cur = c.execute(
            "UPDATE device_tokens SET revoked_at=? WHERE id=? AND revoked_at IS NULL AND user_id="
            "(SELECT id FROM users WHERE username=?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), token_id, username))
        c.commit()
    return cur.rowcount > 0


# ------------------------------------------------------- Cuentas de servicio (integraciones)
# Una integración NO es una persona. Se le da un principal propio para que sus permisos se
# gestionen con el MISMO RBAC que a todo el mundo (user_roles acotado a depto/subcarpeta) y para
# que sobreviva a que quien la creó cambie de puesto o se vaya de la empresa.
def create_service_account(username):
    """Crea una cuenta de servicio. Devuelve True, o False si el nombre ya existe o no vale.

    Nace con una contraseña ALEATORIA que nadie conoce ni puede recuperar: es un requisito de la
    columna, no una credencial. La cuenta no puede iniciar sesión (verify_user rechaza 'service')."""
    username = (username or "").strip()
    if not username or len(username) > 60:
        return False
    with _lock:
        c = _connect()
        if _user_id(c, username) is not None:
            return False
    # Contraseña imposible de adivinar y que nunca sale de aquí.
    create_user(username, secrets.token_urlsafe(48), scope="service")
    return True


def list_service_accounts():
    """Cuentas de servicio con sus carpetas y sus claves activas, para el panel."""
    try:
        with _lock:
            c = _connect()
            rows = c.execute(
                "SELECT username, created_at FROM users WHERE scope='service' ORDER BY username"
            ).fetchall()
    except Exception:
        return []
    out = []
    for name, creado in rows:
        claves = [t for t in list_device_tokens(name) if not t["revoked"]]
        out.append({
            "username": name, "created_at": creado,
            "keys": claves,
            "departments": user_visible_departments(name),
            "subfolders": user_accessible_subfolders(name),
            "remote": has_permission(name, "remote.access"),
        })
    return out


def set_remote_access(username, allow):
    """Concede o retira el permiso de usar la app desde FUERA de la LAN (rol 'remote_client').

    Es la versión por-principal del 'allow_remote' que se pensó como campo de la tabla de claves:
    al vivir en el RBAC, se ve y se audita como cualquier otro permiso."""
    with _lock:
        c = _connect()
        uid = _user_id(c, username)
        if uid is None:
            return False
        c.execute("DELETE FROM user_roles WHERE user_id=? AND department_id IS NULL "
                  "AND subfolder_id IS NULL AND role_id="
                  "(SELECT id FROM roles WHERE name='remote_client')", (uid,))
        if allow:
            _assign_role(c, uid, "remote_client")
        c.commit()
    return True


def is_service_account(username):
    u = get_user(username)
    return bool(u) and u.get("scope") == "service"


# ------------------------------------------------------------------ Novedades (avisos in-app)
# ⚠️ El nombre de la carpeta viaja dentro del texto del evento, con este formato. Escritor y lector
# usan LA MISMA función a propósito: si el formato cambiara en un solo sitio, los avisos dejarían de
# encontrar nada y el fallo sería silencioso.
def folder_tag(dep, sub=None):
    """Prefijo con el que se marca la carpeta en el detalle de un evento de subida."""
    return f"[{dep}/{sub}] " if sub else f"[{dep}] "


UPLOAD_EVENTS = ("upload_dep", "upload_sub")


def mark_folder_seen(username, folder_key):
    """Marca una carpeta como vista AHORA por el usuario (al abrirla)."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _lock:
        c = _connect()
        uid = _user_id(c, username)
        if uid is None:
            return False
        c.execute("INSERT INTO folder_seen (user_id, folder_key, seen_at) VALUES (?,?,?) "
                  "ON CONFLICT(user_id, folder_key) DO UPDATE SET seen_at=excluded.seen_at",
                  (uid, folder_key, ts))
        c.commit()
    return True


def mark_folders_seen(username, folder_keys):
    """Marca VARIAS carpetas como vistas de una vez, sin tener que abrirlas.

    Es lo que permite despachar el aviso desde la pantalla de novedades: si ya sabes lo que ha
    llegado y no te interesa, no deberías estar obligado a entrar en la carpeta para que el
    contador baje. Se hace en una sola transacción para que no queden marcadas a medias.

    Quien llama es responsable de pasar SOLO carpetas a las que el usuario tiene acceso.
    """
    if not folder_keys:
        return 0
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _lock:
        c = _connect()
        uid = _user_id(c, username)
        if uid is None:
            return 0
        c.executemany(
            "INSERT INTO folder_seen (user_id, folder_key, seen_at) VALUES (?,?,?) "
            "ON CONFLICT(user_id, folder_key) DO UPDATE SET seen_at=excluded.seen_at",
            [(uid, k, ts) for k in folder_keys])
        c.commit()
    return len(folder_keys)


def folder_news(username, folder_keys):
    """Novedades por carpeta: {clave: nº de archivos que han dejado OTROS desde tu última visita}.

    No cuenta lo que ha subido uno mismo (nadie necesita que le avisen de su propio archivo).
    Una carpeta nunca vista cuenta TODO lo que hay registrado."""
    out = {}
    if not folder_keys:
        return out
    try:
        with _lock:
            c = _connect()
            uid = _user_id(c, username)
            if uid is None:
                return out
            vistas = dict(c.execute(
                "SELECT folder_key, seen_at FROM folder_seen WHERE user_id=?", (uid,)).fetchall())
            marcas = ",".join("?" * len(UPLOAD_EVENTS))
            for key in folder_keys:
                desde = vistas.get(key, "")
                n = c.execute(
                    f"SELECT COUNT(*) FROM events WHERE type IN ({marcas}) "
                    "AND detail LIKE ? AND ts > ? AND (user IS NULL OR user <> ?)",
                    UPLOAD_EVENTS + (f"[{key}] %", desde, username)).fetchone()[0]
                if n:
                    out[key] = n
    except Exception:
        return {}
    return out


def list_news(username, folder_keys, limit=30):
    """Las novedades en detalle (qué archivo, quién lo dejó, cuándo), más recientes primero."""
    if not folder_keys:
        return []
    items = []
    try:
        with _lock:
            c = _connect()
            uid = _user_id(c, username)
            if uid is None:
                return []
            vistas = dict(c.execute(
                "SELECT folder_key, seen_at FROM folder_seen WHERE user_id=?", (uid,)).fetchall())
            marcas = ",".join("?" * len(UPLOAD_EVENTS))
            for key in folder_keys:
                desde = vistas.get(key, "")
                rows = c.execute(
                    f"SELECT ts, user, detail FROM events WHERE type IN ({marcas}) "
                    "AND detail LIKE ? AND ts > ? AND (user IS NULL OR user <> ?) "
                    "ORDER BY ts DESC LIMIT ?",
                    UPLOAD_EVENTS + (f"[{key}] %", desde, username, limit)).fetchall()
                for ts, quien, detalle in rows:
                    # '[carpeta] archivo · sha256:…' -> nos quedamos con el nombre del archivo
                    resto = detalle[len(f"[{key}] "):] if detalle else ""
                    nombre = resto.split(" · sha256:")[0].strip()
                    items.append({"folder": key, "file": nombre, "who": quien or "—", "ts": ts})
    except Exception:
        return []
    items.sort(key=lambda x: x["ts"], reverse=True)
    return items[:limit]


RBAC_PERMISSIONS = [
    # 'dept.view'  = la carpeta EXISTE para ti (te aparece y puedes abrir su página).
    # 'files.list' = puedes ver el LISTADO de lo que hay dentro. Separado a propósito de
    #                'dept.view': sin él se puede entrar a dejar archivos SIN ver los de
    #                los demás -> es lo que hace posible el "buzón de entrega".
    "dept.view", "files.list", "files.upload", "files.download", "files.delete",
    "depts.manage", "users.manage", "roles.manage", "audit.view",
    "apikeys.manage", "config.manage", "remote.access", "security.manage",
]
RBAC_ROLES = {
    # roles de negocio -> se asignan ACOTADOS a un departamento
    "employee": ["dept.view", "files.list", "files.upload", "files.download"],
    "head":     ["dept.view", "files.list", "files.upload", "files.download", "files.delete"],
    # 'folder_owner': dueño de UNA subcarpeta (acceso pleno dentro de ella). No es jerárquico:
    #                 no hereda hacia otras subcarpetas, a diferencia de 'head'/'director'.
    "folder_owner": ["dept.view", "files.list", "files.upload", "files.download", "files.delete"],
    # --- roles ASIMÉTRICOS (el patrón "buzón de entrega") -------------------------------
    # 'depositor': entra y DEJA archivos, pero NO ve lo que hay dentro. Es el que se da a
    #              quienes envían habitualmente algo a la carpeta de otra persona.
    "depositor": ["dept.view", "files.upload"],
    # 'reader':    ve y descarga, pero no puede subir ni borrar.
    "reader":    ["dept.view", "files.list", "files.download"],
    # acceso a TODOS los deptos -> se asigna GLOBAL. Es el 'boss'/director de hoy.
    "director": ["dept.view", "files.list", "files.upload", "files.download", "files.delete"],
    # sysadmin -> se asigna GLOBAL. Solo gestión; al admin se le añade además 'director'
    # en la migración para conservar su acceso actual a todos los departamentos.
    "it_admin": ["users.manage", "depts.manage", "roles.manage", "audit.view",
                 "apikeys.manage", "config.manage", "security.manage", "remote.access"],
    # Solo concede salir del candado LAN. Se asigna GLOBAL y a mano, normalmente a una cuenta de
    # servicio que deba llamar desde fuera de la red. No da acceso a ninguna carpeta por sí solo.
    "remote_client": ["remote.access"],
}


def _seed_rbac(c):
    """Crea permisos y roles builtin con sus relaciones. Idempotente."""
    for key in RBAC_PERMISSIONS:
        c.execute("INSERT OR IGNORE INTO permissions (key) VALUES (?)", (key,))
    for name, perms in RBAC_ROLES.items():
        c.execute("INSERT OR IGNORE INTO roles (name, builtin) VALUES (?, 1)", (name,))
        rid = c.execute("SELECT id FROM roles WHERE name=?", (name,)).fetchone()[0]
        for key in perms:
            pid = c.execute("SELECT id FROM permissions WHERE key=?", (key,)).fetchone()[0]
            c.execute("INSERT OR IGNORE INTO role_permissions (role_id, permission_id) "
                      "VALUES (?, ?)", (rid, pid))


def _assign_role(c, user_id, role_name, department_id=None):
    r = c.execute("SELECT id FROM roles WHERE name=?", (role_name,)).fetchone()
    if r:
        c.execute("INSERT OR IGNORE INTO user_roles (user_id, role_id, department_id) "
                  "VALUES (?, ?, ?)", (user_id, r[0], department_id))


def _sync_user_global_roles(c, user_id):
    """Ajusta las asignaciones GLOBALES (it_admin/director) de un usuario según su scope/boss.
    Mantiene el RBAC en sync al crear/actualizar usuario o cambiar 'boss'."""
    row = c.execute("SELECT scope, boss FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        return
    scope, boss = row
    c.execute("DELETE FROM user_roles WHERE user_id=? AND department_id IS NULL "
              "AND subfolder_id IS NULL AND role_id IN "
              "(SELECT id FROM roles WHERE name IN ('it_admin','director'))", (user_id,))
    if scope == "admin":
        _assign_role(c, user_id, "it_admin")
        _assign_role(c, user_id, "director")   # conserva acceso a todos los deptos
    elif boss:
        _assign_role(c, user_id, "director")


def _sync_membership_role(c, user_id, department_id, role):
    """Ajusta el rol ACOTADO (employee/head) de un usuario en un depto. role=None -> quitarlo."""
    c.execute("DELETE FROM user_roles WHERE user_id=? AND department_id=? AND role_id IN "
              "(SELECT id FROM roles WHERE name IN ('employee','head'))", (user_id, department_id))
    if role:
        _assign_role(c, user_id, "head" if role == "head" else "employee", department_id)


def _migrate_rbac(c):
    """Traduce el modelo viejo a user_roles. Idempotente; NO borra nada del modelo viejo."""
    # Usuarios: admin -> it_admin + director (global); boss (no admin) -> director (global).
    for uid, scope, boss in c.execute("SELECT id, scope, boss FROM users").fetchall():
        if scope == "admin":
            _assign_role(c, uid, "it_admin")
            _assign_role(c, uid, "director")   # conserva acceso a todos los deptos
        elif boss:
            _assign_role(c, uid, "director")
    # Membresías: member -> employee (acotado); head -> head (acotado).
    for uid, did, role in c.execute(
            "SELECT user_id, department_id, role FROM memberships").fetchall():
        _assign_role(c, uid, "head" if role == "head" else "employee", did)


# Roles cuya autoridad BAJA a las subcarpetas. El resto (employee, depositor, reader) vale solo
# donde se le asignó: pertenecer a un departamento NO da acceso a sus subcarpetas privadas.
RBAC_INHERIT_ROLES = ("head", "director", "it_admin")


def has_permission(username, perm, dept_slug=None, sub_slug=None):
    """¿'username' tiene el permiso 'perm'? Requiere usuario activo.

    - Sin 'dept_slug': solo cuentan las asignaciones GLOBALES.
    - Con 'dept_slug': vale una global o una acotada a ese departamento.
    - Con 'sub_slug': se pregunta por una SUBCARPETA, y la regla es distinta a propósito —
      hace falta una asignación EXPLÍCITA sobre esa subcarpeta, o tener un rol jerárquico
      (head/director/it_admin) sobre el departamento. Ser 'employee' del depto NO basta:
      las subcarpetas son privadas desde que nacen (decisión de Nicolás, 2026-08-25).

    ⚠️ Ojo con las asignaciones de subcarpeta al preguntar por departamento: llevan
    department_id NULL, que en la consulta de depto significaría "global". Por eso todas las
    ramas que no son de subcarpeta exigen 'ur.subfolder_id IS NULL'."""
    try:
        with _lock:
            c = _connect()
            base = ("SELECT 1 FROM user_roles ur "
                    "JOIN users u ON u.id = ur.user_id "
                    "JOIN roles r ON r.id = ur.role_id "
                    "JOIN role_permissions rp ON rp.role_id = ur.role_id "
                    "JOIN permissions p ON p.id = rp.permission_id "
                    "WHERE u.username = ? AND u.status = 'active' AND p.key = ? ")
            if sub_slug:
                marks = ",".join("?" * len(RBAC_INHERIT_ROLES))
                row = c.execute(
                    base +
                    "AND ( ur.subfolder_id = (SELECT sf.id FROM subfolders sf "
                    "        JOIN departments d ON d.id = sf.department_id "
                    "        WHERE d.slug = ? AND sf.slug = ?) "
                    "   OR ( r.name IN (" + marks + ") AND ur.subfolder_id IS NULL "
                    "        AND (ur.department_id IS NULL "
                    "             OR ur.department_id = (SELECT id FROM departments WHERE slug = ?)) "
                    "      ) ) LIMIT 1",
                    (username, perm, dept_slug, sub_slug) + RBAC_INHERIT_ROLES
                    + (dept_slug,)).fetchone()
            else:
                row = c.execute(
                    base +
                    "AND ur.subfolder_id IS NULL "
                    "AND (ur.department_id IS NULL "
                    "     OR ur.department_id = (SELECT id FROM departments WHERE slug = ?)) "
                    "LIMIT 1",
                    (username, perm, dept_slug)).fetchone()
        return row is not None
    except Exception:
        return False


# ------------------------------------------------------------------ Backup
def backup_db(dest_path):
    """Copia CONSISTENTE de la BD con la Online Backup API de SQLite.

    Segura en caliente y con WAL (a diferencia de copiar el .db con cp/tar, que
    puede quedar a medias). Devuelve la ruta del backup creado."""
    dest_path = os.path.abspath(dest_path)
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    with _lock:
        src = _connect()
        dst = sqlite3.connect(dest_path)
        try:
            src.backup(dst)                        # snapshot atómico
            dst.execute("PRAGMA journal_mode=DELETE")  # backup autocontenido (sin -wal)
        finally:
            dst.close()
    try:
        os.chmod(dest_path, 0o600)
    except OSError:
        pass
    return dest_path


def log_event(type, user=None, origin=None, ip=None, detail=None, bytes=None):
    """Inserta un evento. Nunca lanza: si algo falla, la app sigue funcionando."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")   # hora local del servidor
    try:
        with _lock:
            c = _connect()
            c.execute(
                "INSERT INTO events (ts,type,user,origin,ip,detail,bytes) "
                "VALUES (?,?,?,?,?,?,?)",
                (ts, type, user, origin, ip, detail, bytes))
            c.commit()
    except Exception:
        pass


_COLS = ("id", "ts", "type", "user", "origin", "ip", "detail", "bytes")


def recent_events(limit=100):
    """Devuelve los últimos eventos (más nuevos primero) como lista de dicts."""
    try:
        with _lock:
            c = _connect()
            cur = c.execute(
                "SELECT id,ts,type,user,origin,ip,detail,bytes "
                "FROM events ORDER BY id DESC LIMIT ?", (int(limit),))
            rows = cur.fetchall()
        return [dict(zip(_COLS, r)) for r in rows]
    except Exception:
        return []


def search_events(limit=200, desde=None, hasta=None, tipo=None, usuario=None, texto=None):
    """Busca en la auditoría. Todos los filtros son opcionales y se combinan con Y.

    - desde / hasta: 'YYYY-MM-DD' o 'YYYY-MM-DD HH:MM'. Como `ts` se guarda como texto ordenable
      ('YYYY-MM-DD HH:MM:SS'), comparar cadenas ES comparar fechas, y el índice de `ts` sirve.
      A 'hasta' se le añade lo que falte para llegar al final de ese día/minuto: quien escribe
      'hasta el 26' espera que el 26 entre, no que se corte a las 00:00.
    - tipo / usuario: coincidencia exacta.
    - texto: subcadena en el detalle o en la IP.

    Todo va con parámetros ligados: el texto que escribe quien busca NUNCA se concatena al SQL.
    """
    condiciones, valores = [], []

    if desde:
        condiciones.append("ts >= ?")
        valores.append(desde if len(desde) > 10 else desde + " 00:00:00")
    if hasta:
        # 'YYYY-MM-DD' -> hasta el final del día; 'YYYY-MM-DD HH:MM' -> hasta el final del minuto.
        relleno = {10: " 23:59:59", 13: ":59:59", 16: ":59"}.get(len(hasta), "")
        condiciones.append("ts <= ?")
        valores.append(hasta + relleno)
    if tipo:
        condiciones.append("type = ?")
        valores.append(tipo)
    if usuario:
        condiciones.append("user = ?")
        valores.append(usuario)
    if texto:
        # '%' y '_' escritos por quien busca son literales, no comodines: si alguien busca "50%"
        # espera encontrar "50%", no cualquier cosa. De ahí el ESCAPE.
        patron = "%" + (texto.replace("!", "!!").replace("%", "!%").replace("_", "!_")) + "%"
        condiciones.append("(detail LIKE ? ESCAPE '!' OR ip LIKE ? ESCAPE '!')")
        valores.extend([patron, patron])

    donde = (" WHERE " + " AND ".join(condiciones)) if condiciones else ""
    try:
        with _lock:
            c = _connect()
            cur = c.execute(
                "SELECT id,ts,type,user,origin,ip,detail,bytes FROM events" + donde
                + " ORDER BY id DESC LIMIT ?", (*valores, int(limit)))
            rows = cur.fetchall()
        return [dict(zip(_COLS, r)) for r in rows]
    except Exception:
        return []


def event_types():
    """Tipos de evento que existen de verdad en la BD, para poblar el desplegable del filtro.
    Se sacan de los datos y no de una lista fija: así no hace falta acordarse de actualizarla."""
    try:
        with _lock:
            c = _connect()
            return [r[0] for r in c.execute(
                "SELECT DISTINCT type FROM events ORDER BY type")]
    except Exception:
        return []


def event_users():
    """Usuarios que aparecen en la auditoría, para el desplegable del filtro."""
    try:
        with _lock:
            c = _connect()
            return [r[0] for r in c.execute(
                "SELECT DISTINCT user FROM events WHERE user IS NOT NULL AND user <> '' "
                "ORDER BY user")]
    except Exception:
        return []


def stats():
    """Conteo de eventos por tipo (para estadísticas)."""
    try:
        with _lock:
            c = _connect()
            cur = c.execute("SELECT type, COUNT(*) FROM events GROUP BY type ORDER BY 2 DESC")
            return dict(cur.fetchall())
    except Exception:
        return {}


# ------------------------------------------------------------------- CLI
if __name__ == "__main__":
    import sys
    args = sys.argv[1:]
    if len(args) >= 2 and args[0] == "log":
        init_db()
        t = args[1]
        detail = args[2] if len(args) > 2 else None
        b = int(args[3]) if len(args) > 3 and args[3].isdigit() else None
        log_event(t, origin="local", detail=detail, bytes=b)
        print("ok")
    elif args and args[0] == "show":
        n = int(args[1]) if len(args) > 1 and args[1].isdigit() else 20
        for e in recent_events(n):
            print(f"{e['ts']}  {e['type']:<12} {e['origin'] or '':<7} "
                  f"{e['user'] or '':<10} {e['detail'] or ''}  {e['bytes'] or ''}")
    elif len(args) >= 4 and args[0] == "user" and args[1] == "add":
        # db.py user add <usuario> <contraseña> <scope>
        init_db()
        create_user(args[2], args[3], args[4] if len(args) > 4 else "local")
        print(f"usuario '{args[2]}' creado/actualizado")
    elif len(args) >= 3 and args[0] == "user" and args[1] == "del":
        delete_user(args[2]); print(f"usuario '{args[2]}' borrado")
    elif len(args) >= 2 and args[0] == "user" and args[1] == "list":
        init_db()
        for u in list_users():
            print(f"{u['username']:<14} {u['scope']:<7} {u['created_at']}")
    elif len(args) >= 2 and args[0] == "backup":
        # db.py backup <ruta_destino.db>  -> copia consistente de la BD
        init_db()
        print(f"backup de la BD -> {backup_db(args[1])}")
    else:
        print("uso: db.py log <tipo> [detalle] [bytes]  |  db.py show [N]  |  "
              "db.py user add <usr> <pass> <scope>  |  db.py user list  |  db.py user del <usr>  |  "
              "db.py backup <destino.db>")
