"""Pruebas de extremo a extremo de Hylanlock contra una instancia REAL (ver tests/harness.py).

Ejecutar desde la carpeta hylanlock:
    python -m unittest discover -s tests -v

Cada clase levanta su propio servidor con datos temporales y lo para al acabar. No tocan tu app/data.
"""
import glob
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import unittest
import urllib.parse

from harness import APP, Instance, db

import totp  # noqa: E402  (harness ya añadió app/ al sys.path)


def events(inst, *types):
    con = sqlite3.connect(inst.path("hylanlock.db"))
    marks = ",".join("?" * len(types))
    rows = con.execute(f"SELECT type, user, ip, detail FROM events WHERE type IN ({marks}) ORDER BY id",
                       types).fetchall()
    con.close()
    return rows


class TestBasico(unittest.TestCase):
    """Lo mínimo que nunca debe romperse: login, candados y CSRF."""

    @classmethod
    def setUpClass(cls):
        cls.inst = Instance()
        cls.inst.db()
        db.create_user("admin", "pass-admin-123", scope="admin")
        db.create_user("ana", "pass-ana-456", scope="member")
        cls.inst.start()

    @classmethod
    def tearDownClass(cls):
        cls.inst.stop()

    def test_healthz_y_login(self):
        c = self.inst.client()
        self.assertEqual(c.get("/healthz")[0], 200)
        self.assertEqual(c.login("admin", "mal"), 200)            # vuelve al formulario con error
        self.assertNotIn("pr_token", c.cookies())
        self.assertEqual(c.login("admin", "pass-admin-123"), 302)
        self.assertIn("pr_token", c.cookies())

    def test_sin_sesion_no_hay_nada(self):
        c = self.inst.client()
        self.assertEqual(c.get("/admin")[0], 302)
        self.assertEqual(c.get("/api/departamentos")[0], 401)

    def test_miembro_no_administra(self):
        c = self.inst.client()
        c.login("ana", "pass-ana-456")
        self.assertEqual(c.get("/admin")[0], 403)
        self.assertEqual(c.get("/gobernanza")[0], 403)

    def test_post_sin_csrf_rechazado(self):
        c = self.inst.client()
        c.login("admin", "pass-admin-123")
        self.assertEqual(c.post("/admin/dep/add", {"name": "Sin token"})[0], 403)
        self.assertIn(c.post_csrf("/admin/dep/add", {"name": "Con token"}, page="/admin")[0], (200, 302))
        nombres = [d["name"] for d in db.list_departments()]
        self.assertIn("Con token", nombres)
        self.assertNotIn("Sin token", nombres)

    def test_cabeceras_de_seguridad(self):
        _, _, h = self.inst.client().get("/login")
        self.assertIn("frame-ancestors 'none'", h.get("Content-Security-Policy", ""))
        self.assertEqual(h.get("X-Frame-Options"), "DENY")


class TestNombresSeguros(unittest.TestCase):
    """Un nombre de archivo con HTML no debe guardarse tal cual (subida por API) ni pintarse sin escapar."""

    @classmethod
    def setUpClass(cls):
        cls.inst = Instance()
        cls.inst.db()
        db.create_user("admin", "pass-admin-123", scope="admin")
        db.create_department("Ventas")
        db.create_service_account("erp")
        db.add_membership("erp", "ventas")
        cls.token = db.create_device_token("erp", "integración de pruebas")
        cls.inst.start()

    @classmethod
    def tearDownClass(cls):
        cls.inst.stop()

    def test_api_sanea_el_nombre(self):
        malo = '<img src=x onerror="alert(1)">factura.pdf'
        s, body, _ = self.inst.client().post(
            "/api/v1/upload?folder=ventas&name=" + urllib.parse.quote(malo), b"contenido",
            {"Authorization": "Bearer " + self.token})
        self.assertEqual(s, 400, body)                    # se rechaza y se dice (contrato de máquina)
        self.assertIn("caracteres", body)
        self.assertEqual(os.listdir(self.inst.path("departamentos", "ventas")), [])   # no se guardó nada
        s, body, _ = self.inst.client().post("/api/v1/upload?folder=ventas&name=factura.pdf", b"contenido",
                                             {"Authorization": "Bearer " + self.token})
        self.assertEqual((s, json.loads(body)["name"]), (201, "factura.pdf"))          # un nombre normal, sí

    def test_plantillas_escapan_los_nombres(self):
        for pagina, trozo in (("departamento.html", "${esc(f.name)}"), ("departamentos.html", "${esc(d.name)}")):
            with open(os.path.join(APP, "web", pagina), encoding="utf-8") as f:
                self.assertIn(trozo, f.read(), pagina)


class TestBuzon(unittest.TestCase):
    """Enlace de buzón: un externo deja un archivo sin cuenta; queda auditado y el enlace se cierra."""

    @classmethod
    def setUpClass(cls):
        cls.inst = Instance()
        cls.inst.db()
        db.create_user("admin", "pass-admin-123", scope="admin")
        db.create_department("Clientes")
        db.create_subfolder("clientes", "Subidas")
        cls.token = db.create_buzon_link("clientes", "subidas", "Facturas", "admin")    # 24 h, un archivo
        cls.inst.start()

    @classmethod
    def tearDownClass(cls):
        cls.inst.stop()

    def test_entrega_completa_y_cierre(self):
        c = self.inst.client()
        s, body, _ = c.get(f"/b/{self.token}")
        self.assertEqual(s, 200)
        self.assertIn("Dejar un archivo", body)
        datos = b"factura de prueba"
        s, _, _ = c.post(f"/b/{self.token}/chunk", datos, {"X-Upload-Id": "t01", "X-Offset": "0"})
        self.assertEqual(s, 200)
        s, _, _ = c.post(f"/b/{self.token}/complete?id=t01", b"",
                         {"X-Filename": urllib.parse.quote("factura.pdf"),
                          "X-Dropper": urllib.parse.quote("Juan Pérez")})
        self.assertEqual(s, 200)
        found = glob.glob(self.inst.path("**", "factura.pdf"), recursive=True)
        self.assertTrue(found, "el archivo no llegó a la carpeta")
        ev = events(self.inst, "upload_sub")[-1]
        self.assertEqual(ev[2], "127.0.0.1")                     # la IP queda en la auditoría
        self.assertIn("Juan", ev[1] or "")
        # Un solo archivo: el enlace ya no admite más
        self.assertIn("no disponible", c.get(f"/b/{self.token}")[1].lower())

    def test_token_falso(self):
        self.assertIn("no disponible", self.inst.client().get("/b/inventado123")[1].lower())


class TestExposicion(unittest.TestCase):
    """Aviso de exposición: una petición desde una IP pública se detecta sin consultar nada externo.
    Se simula 'internet' con un proxy de confianza (127.0.0.1) que reenvía X-Forwarded-For."""

    @classmethod
    def setUpClass(cls):
        cls.inst = Instance()
        cls.inst.db()
        db.create_user("admin", "pass-admin-123", scope="admin")
        db.create_user("ana", "pass-ana-456", scope="member")
        cls.inst.start(TRUSTED_PROXIES="127.0.0.1/32")

    @classmethod
    def tearDownClass(cls):
        cls.inst.stop()

    def test_deteccion_banner_y_revisado(self):
        adm = self.inst.client()
        adm.login("admin", "pass-admin-123")
        self.assertIn("No se ha detectado", adm.get("/ajustes")[1])
        anon = self.inst.client()
        for ip in ("8.8.8.8", "1.1.1.1"):
            anon.get("/login", {"X-Forwarded-For": ip})
        anon.get("/login", {"X-Forwarded-For": "192.168.1.20"})   # privada: no cuenta
        body = adm.get("/ajustes")[1]
        self.assertIn("expo-banner", body)
        self.assertIn("2 IPs nuevas", body)
        self.assertNotIn("192.168.1.20", body)
        ana = self.inst.client()
        ana.login("ana", "pass-ana-456")
        self.assertNotIn("expo-banner", ana.get("/")[1])          # solo lo ven los admins
        self.assertEqual(adm.post_csrf("/admin/exposicion/revisado")[0], 200)
        self.assertNotIn("expo-banner", adm.get("/")[1])
        anon.get("/login", {"X-Forwarded-For": "4.4.4.4"})        # IP nueva -> vuelve el aviso
        self.assertIn("1 IP nueva", adm.get("/")[1])
        self.assertEqual(len(events(self.inst, "public_access")), 3)


class TestGobernanza(unittest.TestCase):
    """Gestionar sin leer: el Supervisor ve la estructura, pero ni nombres ni contenido."""

    SECRETOS = ["oferta-acme", "despido-juan", "nomina-marzo"]

    @classmethod
    def setUpClass(cls):
        cls.inst = Instance()
        cls.inst.db()
        db.create_user("admin", "pass-admin-123", scope="admin")
        for u in ("ana", "dpo", "pepe"):
            db.create_user(u, "pass-user-456", scope="member")
        db.create_department("Ventas")
        db.create_department("RRHH")
        db.add_membership("ana", "ventas")
        db.create_subfolder("rrhh", "Nominas")
        db.set_supervisor("dpo", True)
        base = cls.inst.path("departamentos")
        contrato = b"CONTRATO" * 80

        def put(rel, data, dias=0, quien=None, tag=None):
            p = os.path.join(base, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(data)
            h = hashlib.sha256(data).hexdigest()
            with open(p + ".sha256", "w", newline="") as f:
                f.write(f"{h} *{os.path.basename(p)}\n")
            if dias:
                t = time.time() - dias * 86400
                os.utime(p, (t, t))
            if quien:
                db.log_event("upload_dep", user=quien, origin="local", ip="127.0.0.1",
                             detail=f"[{tag}] {os.path.basename(p)} · sha256:{h[:12]}…")
        put("ventas/oferta-acme.pdf", b"oferta" * 100, quien="ana", tag="ventas")
        put("ventas/contrato.pdf", contrato, quien="ana", tag="ventas")
        put("rrhh/nominas/despido-juan.pdf", contrato, dias=400)          # duplicado y antiguo
        put("rrhh/nominas/nomina-marzo.xlsx", b"nomina", dias=200)
        cls.inst.start()

    @classmethod
    def tearDownClass(cls):
        cls.inst.stop()

    def datos(self, client):
        s, body, _ = client.get("/gobernanza")
        self.assertEqual(s, 200)
        for secreto in self.SECRETOS:
            self.assertNotIn(secreto, body, "un nombre de archivo ha llegado al navegador")
        return json.loads(re.search(r"const GOV = (\{.*?\});\n", body, re.S).group(1))

    def test_cifras(self):
        adm = self.inst.client()
        adm.login("admin", "pass-admin-123")
        k = self.datos(adm)["kpi"]
        self.assertEqual((k["deps"], k["subs"], k["files"]), (2, 1, 4))
        self.assertEqual((k["dup_copies"], k["old_files"], k["stale"], k["empty"]), (1, 1, 1, 1))

    def test_supervisor_ve_pero_no_lee(self):
        dpo = self.inst.client()
        dpo.login("dpo", "pass-user-456")
        self.assertEqual(self.datos(dpo)["supervisors"], ["dpo"])
        self.assertEqual(dpo.get("/api/dep/ventas")[0], 403)                       # no lista
        self.assertEqual(dpo.get("/dep/ventas/download?f=oferta-acme.pdf")[0], 403)  # no descarga
        self.assertEqual(dpo.get("/admin")[0], 403)                                # no administra

    def test_rol_supervisor_desde_admin(self):
        pepe = self.inst.client()
        pepe.login("pepe", "pass-user-456")
        self.assertEqual(pepe.get("/gobernanza")[0], 403)
        adm = self.inst.client()
        adm.login("admin", "pass-admin-123")
        self.assertEqual(adm.post_csrf("/admin/user/supervisor", {"username": "pepe", "on": "1"}, "/admin")[0], 200)
        self.assertEqual(pepe.get("/gobernanza")[0], 200)
        adm.post_csrf("/admin/user/supervisor", {"username": "pepe", "on": ""}, "/admin")
        self.assertEqual(pepe.get("/gobernanza")[0], 403)


class TestCopiasDeSeguridad(unittest.TestCase):
    """Ajustes dice cuándo fue la última copia (la apunta scripts/backup.sh con db.py backup-done)."""

    @classmethod
    def setUpClass(cls):
        cls.inst = Instance()
        cls.inst.db()
        db.create_user("admin", "pass-admin-123", scope="admin")
        cls.inst.start()

    @classmethod
    def tearDownClass(cls):
        cls.inst.stop()

    def test_sin_copia_reciente_y_antigua(self):
        adm = self.inst.client()
        adm.login("admin", "pass-admin-123")
        self.assertIn("No consta ninguna copia", adm.get("/ajustes")[1])
        env = {**os.environ, "HYLANLOCK_DATA_DIR": self.inst.dir, "PYTHONIOENCODING": "utf-8"}
        env.pop("HYLANLOCK_DB_PATH", None)
        subprocess.run([sys.executable, "db.py", "backup-done", "hylanlock-20261018-030000.tar.gz", "12M", "/backups"],
                       cwd=APP, env=env, capture_output=True, check=True)
        body = adm.get("/ajustes")[1]
        self.assertIn("Última copia", body)
        self.assertIn("hylanlock-20261018-030000.tar.gz", body)
        self.assertNotIn("Hace demasiado", body)
        db.meta_set("last_backup", json.dumps({"ts": time.time() - 5 * 86400, "file": "vieja.tar.gz"}))
        self.assertIn("Hace demasiado", adm.get("/ajustes")[1])
        self.assertEqual(events(self.inst, "backup_ok")[-1][1], "copia automática")


class TestPapelera(unittest.TestCase):
    """Borrado blando: solo admins borran/restauran/eliminan; restaurar vuelve a su sitio sin pisar nada."""

    @classmethod
    def setUpClass(cls):
        cls.inst = Instance()
        cls.inst.db()
        db.create_user("admin", "pass-admin-123", scope="admin")
        db.create_user("ana", "pass-ana-456", scope="member")
        db.create_department("Ventas")
        db.add_membership("ana", "ventas", "head")          # jefa: tiene files.delete, pero NO borra (solo admins)
        for n in ("a.pdf", "b.pdf", "c.pdf", "d.pdf", "e.pdf"):
            cls.put(n)
        cls.inst.start()
        cls.adm = cls.inst.client()
        cls.adm.login("admin", "pass-admin-123")

    @classmethod
    def tearDownClass(cls):
        cls.inst.stop()

    @classmethod
    def put(cls, name, data=None):
        p = cls.inst.path("departamentos", "ventas", name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        data = data or name.encode() * 10
        with open(p, "wb") as f:
            f.write(data)
        with open(p + ".sha256", "w", newline="") as f:
            f.write(f"{hashlib.sha256(data).hexdigest()} *{name}\n")

    def carpeta(self):
        return sorted(os.listdir(self.inst.path("departamentos", "ventas")))

    def borrar(self, name, client=None):
        return (client or self.adm).post_csrf("/admin/papelera/borrar", {"dep": "ventas", "file": name}, "/papelera")

    def papelera(self):
        body = self.adm.get("/papelera")[1]
        return json.loads(re.search(r"const DATA = (\{.*?\});\n", body, re.S).group(1))["items"]

    def item(self, name):
        return next(i for i in self.papelera() if i["name"] == name)

    def test_solo_admins(self):
        ana = self.inst.client()
        ana.login("ana", "pass-ana-456")
        self.assertIn("const CAN_DELETE = false", ana.get("/dep/ventas")[1])
        self.assertIn("const CAN_DELETE = true", self.adm.get("/dep/ventas")[1])
        self.assertEqual(self.borrar("a.pdf", ana)[0], 403)
        self.assertEqual(ana.get("/papelera")[0], 403)
        self.assertIn("a.pdf", self.carpeta())

    def test_borrar_y_restaurar_sin_pisar(self):
        self.assertEqual(self.borrar("b.pdf")[0], 200)
        self.assertNotIn("b.pdf", self.carpeta())
        self.assertNotIn("b.pdf.sha256", self.carpeta())             # la huella se va con él
        it = self.item("b.pdf")
        self.assertEqual((it["folder"], it["deleted_by"]), ("ventas", "admin"))
        self.put("b.pdf", b"otro distinto")                         # mientras, alguien sube otro b.pdf
        s, body, _ = self.adm.post_csrf("/admin/papelera/restaurar", {"id": it["id"]}, "/papelera")
        self.assertEqual((s, json.loads(body)["name"]), (200, "b (1).pdf"))
        self.assertIn("b (1).pdf", self.carpeta())
        with open(self.inst.path("departamentos", "ventas", "b.pdf"), "rb") as f:
            self.assertEqual(f.read(), b"otro distinto")             # el nuevo no se ha tocado
        with open(self.inst.path("departamentos", "ventas", "b (1).pdf.sha256")) as f:
            self.assertIn("*b (1).pdf", f.read())                    # sidecar reescrito con el nombre nuevo
        self.assertEqual(events(self.inst, "file_trash", "file_restore")[-1][0], "file_restore")

    def test_eliminar_definitivo(self):
        self.borrar("c.pdf")
        it = self.item("c.pdf")
        self.assertEqual(self.adm.post_csrf("/admin/papelera/eliminar", {"id": it["id"]}, "/papelera")[0], 200)
        self.assertNotIn("c.pdf", [i["name"] for i in self.papelera()])
        self.assertFalse(os.path.exists(self.inst.path(".papelera", str(it["id"]))))
        self.assertIn("c.pdf", events(self.inst, "file_purge")[-1][3])

    def test_vaciado_automatico_y_cero_es_nunca(self):
        def envejecer(name):
            con = sqlite3.connect(self.inst.path("hylanlock.db"))
            con.execute("UPDATE trash SET deleted_at='2000-01-01 00:00:00' WHERE name=?", (name,))
            con.commit()
            con.close()
        self.borrar("d.pdf")
        envejecer("d.pdf")
        self.assertNotIn("d.pdf", [i["name"] for i in self.papelera()])     # con 30 días: eliminado
        self.assertIn("d.pdf", events(self.inst, "trash_autopurge")[-1][3])
        self.assertEqual(self.adm.post_csrf("/admin/config/papelera", {"days": "0"}, "/ajustes")[0], 200)
        try:
            self.borrar("e.pdf")
            envejecer("e.pdf")
            self.assertIn("e.pdf", [i["name"] for i in self.papelera()])     # con 0: nunca se vacía sola
        finally:
            self.adm.post_csrf("/admin/config/papelera", {"days": "30"}, "/ajustes")

    def test_no_se_sale_de_la_carpeta(self):
        for malo in ("../../hylanlock.db", "..\\..\\license.key", "a.pdf.sha256", "no-existe.pdf"):
            self.assertEqual(self.borrar(malo)[0], 404, malo)
        self.assertTrue(os.path.exists(self.inst.path("hylanlock.db")))
        self.assertTrue(os.path.exists(self.inst.path("license.key")))


class TestDosPasos(unittest.TestCase):
    """2FA (TOTP): activación, login en dos pasos, anti-reutilización, recuperación y política."""

    @classmethod
    def setUpClass(cls):
        cls.inst = Instance()
        cls.inst.db()
        db.create_user("admin", "pass-admin-123", scope="admin")
        db.create_user("admin2", "pass-admin-789", scope="admin")
        db.create_user("admin3", "pass-admin-321", scope="admin")
        db.create_user("ana", "pass-ana-456", scope="member")
        cls.inst.start()

    @classmethod
    def tearDownClass(cls):
        cls.inst.stop()

    @staticmethod
    def code(secret, ahead=0):
        return totp.code_at(secret, int(time.time() // 30) + ahead)

    def activar(self, client):
        j = json.loads(client.post_csrf("/perfil/2fa/iniciar")[1])
        secret = j["secret"]
        s, b, _ = client.post_csrf("/perfil/2fa/activar", {"secret": secret, "code": self.code(secret)})
        self.assertEqual(s, 200)
        return secret, json.loads(b)["recovery"]

    def test_stepup_pide_codigo(self):
        c = self.inst.client()
        c.login("admin3", "pass-admin-321")
        secret, _ = self.activar(c)
        self.assertIn('name="code"', c.get("/elevate?next=/admin")[1])     # con 2FA, el step-up pide código
        s, body, _ = c.post_csrf("/elevate", {"password": "pass-admin-321", "next": "/admin"})
        self.assertEqual(s, 200)                                           # solo contraseña: no basta
        self.assertIn("incorrectos", body)
        s, _, h = c.post_csrf("/elevate", {"password": "pass-admin-321", "code": self.code(secret, 1),
                                           "next": "/admin"})
        self.assertEqual((s, h.get("Location")), (302, "/admin"))
        sin = self.inst.client()
        sin.login("ana", "pass-ana-456")
        self.assertNotIn('name="code"', sin.get("/elevate")[1])           # sin 2FA, como siempre

    def test_totp_rfc6238(self):
        import base64
        s = base64.b32encode(b"12345678901234567890").decode()
        self.assertEqual(totp.code_at(s, 59 // 30, digits=8), "94287082")
        self.assertEqual(totp.code_at(s, 2000000000 // 30, digits=8), "69279037")

    def test_flujo_completo(self):
        adm = self.inst.client()
        adm.login("admin", "pass-admin-123")
        secret, recovery = self.activar(adm)
        self.assertEqual(len(recovery), 8)
        # Contraseña correcta -> todavía NO hay sesión
        c = self.inst.client()
        c.login("admin", "pass-admin-123")
        self.assertNotIn("pr_token", c.cookies())
        self.assertIn("pr_2fa", c.cookies())
        self.assertEqual(c.get("/admin")[0], 302)
        # El código usado al activar no vuelve a valer; el siguiente sí
        c.post("/login/2fa", {"code": self.code(secret)})
        self.assertNotIn("pr_token", c.cookies())
        bueno = self.code(secret, 1)
        self.assertEqual(c.post("/login/2fa", {"code": bueno})[0], 302)
        self.assertIn("pr_token", c.cookies())
        # Ni en otro navegador
        c2 = self.inst.client()
        c2.login("admin", "pass-admin-123")
        c2.post("/login/2fa", {"code": bueno})
        self.assertNotIn("pr_token", c2.cookies())
        # Código de recuperación: una sola vez
        self.assertEqual(c2.post("/login/2fa", {"code": recovery[0]})[0], 302)
        c3 = self.inst.client()
        c3.login("admin", "pass-admin-123")
        c3.post("/login/2fa", {"code": recovery[0]})
        self.assertNotIn("pr_token", c3.cookies())
        # Sin la cookie intermedia no se salta la contraseña
        self.assertEqual(self.inst.client().post("/login/2fa", {"code": self.code(secret, 1)})[0], 302)
        # Rescate desde la consola del servidor
        env = {**os.environ, "HYLANLOCK_DATA_DIR": self.inst.dir, "PYTHONIOENCODING": "utf-8"}
        env.pop("HYLANLOCK_DB_PATH", None)
        subprocess.run([sys.executable, "db.py", "user", "reset-2fa", "admin"], cwd=APP, env=env,
                       capture_output=True, check=True)
        self.assertFalse(db.totp_status("admin")["enabled"])

    def test_politica_obligatoria(self):
        adm = self.inst.client()
        adm.login("admin", "pass-admin-123")
        self.assertEqual(adm.post_csrf("/admin/config/2fa", {"on": "1"}, "/perfil")[0], 200)
        try:
            a2 = self.inst.client()
            a2.login("admin2", "pass-admin-789")
            s, _, h = a2.get("/admin")
            self.assertEqual((s, h.get("Location")), (302, "/perfil?2fa=obligatorio"))
            secret, _ = self.activar(a2)
            self.assertEqual(a2.get("/admin")[0], 200)
            self.assertEqual(a2.post_csrf("/perfil/2fa/desactivar", {"code": self.code(secret, 1)})[0], 409)
            ana = self.inst.client()
            ana.login("ana", "pass-ana-456")
            self.assertEqual(ana.get("/departamentos")[0], 200)                   # a un miembro no le afecta
            self.assertEqual(ana.post_csrf("/perfil/2fa/iniciar")[0], 403)
        finally:
            self.inst.client()
            db.meta_set("require_2fa_admins", "0")
            db.totp_disable("admin2")


if __name__ == "__main__":
    unittest.main()
