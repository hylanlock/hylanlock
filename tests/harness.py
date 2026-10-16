"""Arnés de pruebas de Hylanlock: levanta una instancia REAL en un puerto libre, con datos temporales,
y ofrece un cliente HTTP con cookies. Solo librería estándar.

Licencia de pruebas: no se usa la clave privada de producción (vive fuera del repo, en tools/). Cada
ejecución genera su PROPIO par Ed25519, firma una licencia con él y arranca el servidor a través de
tests/_run_server.py, que sustituye la clave pública embebida por la de pruebas SOLO en ese proceso.
"""
import http.cookiejar
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "app")
sys.path.insert(0, APP)

import db                 # noqa: E402  (después de ajustar sys.path)
import ed25519_pure as ed  # noqa: E402
import license            # noqa: E402

_SK = secrets.token_bytes(32)
TEST_PUBKEY = ed.publickey(_SK)


def test_license(days=30, kind="commercial", customer="Pruebas automáticas"):
    claims = json.dumps({"id": "test-" + secrets.token_hex(4), "customer": customer, "type": kind,
                         "issued": date.today().isoformat(),
                         "expires": (date.today() + timedelta(days=days)).isoformat(),
                         "max_users": 0}).encode()
    return license.pack(claims, ed.sign(claims, _SK, TEST_PUBKEY))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Instance:
    """Una instancia de Hylanlock para pruebas. Uso:

        inst = Instance(); inst.db()            # BD temporal lista para sembrar con db.*
        db.create_user(...)
        inst.start(LAN_CIDR="127.0.0.0/8")      # variables HYLANLOCK_* sin el prefijo
        ...
        inst.stop()
    """

    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="hyltest_")
        with open(os.path.join(self.dir, "license.key"), "w", encoding="ascii") as f:
            f.write(test_license())
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.proc = None

    def db(self):
        """Apunta el módulo db a la BD de ESTA instancia (para sembrar datos antes de arrancar)."""
        if db._conn is not None:
            db._conn.close()
        db._conn = None
        db.DATA_DIR = self.dir
        db.DB_PATH = os.path.join(self.dir, "hylanlock.db")
        db.init_db()
        return db

    def path(self, *parts):
        return os.path.join(self.dir, *parts)

    def start(self, **env):
        e = dict(os.environ)
        e.pop("HYLANLOCK_DB_PATH", None)
        e.update({"HYLANLOCK_DATA_DIR": self.dir, "HYLANLOCK_PORT": str(self.port),
                  "HYLANLOCK_LAN_CIDR": "127.0.0.0/8", "PYTHONIOENCODING": "utf-8",
                  "HYLANLOCK_TEST_LICENSE_PUBKEY": TEST_PUBKEY.hex()})
        e.update({f"HYLANLOCK_{k}": str(v) for k, v in env.items()})
        self.log = open(self.path("servidor.log"), "w", encoding="utf-8")
        self.proc = subprocess.Popen([sys.executable, os.path.join(ROOT, "tests", "_run_server.py")],
                                     cwd=APP, env=e, stdout=self.log, stderr=subprocess.STDOUT)
        for _ in range(80):
            if self.client().get("/healthz")[0] == 200:
                return self
            time.sleep(0.25)
        raise RuntimeError("el servidor de pruebas no arrancó; mira " + self.path("servidor.log"))

    def stop(self):
        if self.proc:
            self.proc.terminate()
            self.proc.wait(10)
            self.log.close()
        if db._conn is not None:
            db._conn.close()
            db._conn = None
        shutil.rmtree(self.dir, ignore_errors=True)

    def server_log(self):
        self.log.flush()
        with open(self.path("servidor.log"), encoding="utf-8") as f:
            return f.read()

    def client(self):
        return Client(self.base)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Client:
    """Navegador mínimo: guarda cookies, no sigue redirecciones (para poder comprobarlas)."""

    def __init__(self, base):
        self.base = base
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), _NoRedirect)

    def request(self, path, data=None, headers=None, method=None):
        h = dict(headers or {})
        if isinstance(data, dict):
            data = urllib.parse.urlencode(data).encode()
            h.setdefault("Content-Type", "application/x-www-form-urlencoded")
        req = urllib.request.Request(self.base + path, data=data, headers=h,
                                     method=method or ("POST" if data is not None else "GET"))
        try:
            with self.op.open(req, timeout=15) as r:
                return r.status, r.read().decode("utf-8", "replace"), r.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace"), e.headers
        except OSError as e:
            return None, str(e), {}

    def get(self, path, headers=None):
        return self.request(path, headers=headers)

    def post(self, path, data=None, headers=None):
        return self.request(path, data if data is not None else b"", headers)

    def cookies(self):
        return {c.name: c.value for c in self.jar}

    def login(self, user, password):
        s, _, _ = self.post("/login", {"username": user, "password": password})
        return s

    def csrf(self, page="/perfil"):
        m = re.search(r'name="hyl-csrf" content="([^"]+)"', self.get(page)[1])
        return m.group(1) if m else ""

    def post_csrf(self, path, data=None, page="/perfil"):
        """POST como lo haría la web: con el token CSRF en la cabecera X-CSRF."""
        return self.post(path, data or {}, {"X-CSRF": self.csrf(page)})
