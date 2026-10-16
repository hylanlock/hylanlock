# 🛠️ Guía del desarrollador de Hylanlock

Manual para seguir construyendo Hylanlock **sin ayuda**: cómo está hecho, cómo viaja una petición,
cómo añadir algo sin abrir agujeros, cómo probar y cómo publicar. Léelo de arriba abajo una vez; después
úsalo como chuleta.

---

## 1. Reglas de oro (antes de tocar nada)

1. **Nada sale de la red.** Ni telemetría, ni "llamar a casa", ni comprobar cosas en servicios externos.
   (Única excepción opcional: avisos de Telegram si el cliente los configura.)
2. **Solo librería estándar de Python.** Cero dependencias: así se audita entero y se instala con un comando.
3. **Fail-closed.** Si algo no está declarado o falla, se **deniega**. Nunca al revés.
4. **Nunca destruir datos en silencio.** Ni siquiera con licencia caducada: se bloquea el uso, no se borra.
5. **Todo lo importante queda en la auditoría** (`db.log_event`).
6. **Si una idea roza la filosofía, se reencuadra o se descarta.** Mejor una feature menos que una promesa rota.

---

## 2. Mapa del código

| Ruta | Qué es |
|---|---|
| `app/hylanlock.py` | **El servidor** (HTTP, rutas, permisos, plantillas, subidas, buzón, 2FA, gobernanza…). ~4.300 líneas. |
| `app/db.py` | Base de datos SQLite: usuarios, departamentos, subcarpetas, **RBAC**, auditoría, 2FA, metadatos. También es una CLI (`python db.py …`). |
| `app/license.py` + `app/ed25519_pure.py` | Verificación **offline** de licencias (firma Ed25519, clave pública embebida). |
| `app/totp.py` | Códigos 2FA (TOTP, RFC 6238). |
| `app/ldap_auth.py` | Login contra Active Directory / LDAP (opcional). |
| `app/qr.py` | Generador de QR local (invitaciones, alta de 2FA). |
| `app/web/*.html` | Plantillas. `layout.html` es el marco (menú lateral); el resto son "fragmentos" que van dentro. |
| `app/web/styles.css` | Estilos y temas (claro/oscuro). |
| `agente/` | Agente de sincronización para los PCs (usa la API `/api/v1`). |
| `tests/` | **Pruebas** de extremo a extremo (ver §7). |
| `docs/` | API, backups, despliegue, HTTPS y esta guía. |
| `scripts/` | `backup.sh` / `restore.sh`. |
| `tools/` | **Interno, NO está en el repo** (`.gitignore`): clave privada y emisor de licencias, empaquetador de releases. |

---

## 3. Arrancar en tu PC

En PowerShell, desde la carpeta `hylanlock`:

```powershell
$env:HYLANLOCK_DEV = "1"
$env:HYLANLOCK_DATA_DIR = "C:\hyl-pruebas"
python app/hylanlock.py
```

- `HYLANLOCK_DEV=1` hace que las plantillas se relean en cada petición: editas un `.html` y recargas el navegador, sin reiniciar. Sin él, se cachean.
- La primera vez abre `http://localhost:8000/setup` (asistente: crea el admin).
- Sin licencia el uso queda bloqueado. Para pruebas, genera una de prueba con `python tools/license_gen.py -c "Pruebas"` y pégala en el asistente o en `/admin/licencia`.
- Usa **siempre una carpeta de datos de pruebas** (`HYLANLOCK_DATA_DIR`), nunca la de un cliente.

---

## 4. Cómo viaja una petición

```
do_GET / do_POST
  │  0) exposure_note(): si la IP es de internet, se apunta (aviso de exposición)
  │  1) Rutas PÚBLICAS, resueltas antes de nada:
  │       /healthz · PWA (manifest, sw.js, iconos) · /setup · /login · /login/2fa · /logout
  │       /activar (invitación) · /b/<token> (enlace de buzón)
  ▼
_enforce(method, path)   ← EL chokepoint. Todo lo demás pasa por aquí, en este orden:
  1) ¿Autenticado? (cookie firmada `pr_token`, o token Bearer para la API)   → si no: 302 /login o 401
  1a) Política "2FA obligatorio a admins": si falta, solo deja ir a Mi perfil
  1a-bis) Límite de peticiones de la API pública
  1b) CSRF en todo POST con cookie (cabecera X-CSRF o campo __csrf__)       → 403
  1c) Licencia válida (si no, solo licencia/exportar para el admin)          → pantalla de bloqueo
  2) Guarda de la ruta en _GUARD_GET / _GUARD_POST. ¿No existe? → 404 (fail-closed)
  3) Candado LAN (`"lan": True`): fuera de la red local, 403
  4) Permiso RBAC (`"perm": "..."`, opcionalmente sobre el departamento/subcarpeta)
  5) Step-up (`"elevated": True`): hay que haber confirmado la contraseña (y el código 2FA) hace poco
  ▼
handler de la ruta (el `elif path == ...` correspondiente)
```

**Detalles que importan:**
- **Sesión:** cookie `pr_token` = `usuario|scope|token_version|elevación|recordarme|caducidad` firmada con HMAC (`make_session`). Subir `token_version` en la BD invalida todas las sesiones de ese usuario al instante.
- **Step-up:** iniciar sesión cuenta como elevación durante `STEPUP_MINUTES` (15). Después, las rutas `elevated` mandan a `/elevate`.
- **CSRF:** no hay que hacer nada en las páginas. `_send` inyecta el token y un script que lo añade solo a todo `fetch`/formulario POST.
- **IP del cliente:** `_client_ip()`. Solo se cree `X-Forwarded-For` si la conexión viene de un proxy de `HYLANLOCK_TRUSTED_PROXIES`. **Nunca leas cabeceras de IP a mano.**

---

## 5. Permisos (RBAC)

Todo vive en `app/db.py`:

- `RBAC_PERMISSIONS`: la lista de permisos (`dept.view`, `files.list`, `files.upload`, `files.download`, `files.delete`, `users.manage`, `audit.view`, `remote.access`, `folder.oversee`…).
- `RBAC_ROLES`: qué permisos tiene cada rol (`employee`, `head`, `depositor`, `reader`, `director`, `it_admin`, `supervisor`…).
- `has_permission(usuario, permiso, dep, sub)`: la **única** fuente de verdad. En el servidor se usa con `self._has(...)`.
- Los roles se asignan **globales** (sin departamento), **por departamento** o **por subcarpeta**.
- **Las subcarpetas son privadas desde que nacen:** ser `employee` del departamento no basta. Solo heredan `head`, `director` e `it_admin`.
- El **admin** es `it_admin` (gestión) + `director` (acceso a todo). El **Supervisor** solo tiene `folder.oversee`: ve Gobernanza, pero ni lista ni descarga.

**Añadir un permiso o un rol:** agrégalo a `RBAC_PERMISSIONS` / `RBAC_ROLES`. `_seed_rbac` es idempotente y corre en cada arranque, así que las instalaciones existentes lo reciben solas.

---

## 6. Receta: añadir una ruta nueva sin abrir agujeros

1. **Guarda primero.** Añade la ruta a `_GUARD_GET` o `_GUARD_POST`:
   ```python
   "/admin/mi-cosa": {"lan": True, "perm": "users.manage", "elevated": True},
   ```
   - `lan`: casi siempre `True`. `perm`: el permiso mínimo. `elevated`: si cambia algo delicado (usuarios, seguridad, config).
   - Sin guarda, la ruta da 404 (es a propósito).
2. **Handler.** Añade el `elif path == "/admin/mi-cosa":` en `do_GET` o en el bloque de POST autenticados.
   - Lee el cuerpo con `parse_qs(self._read_body().decode("utf-8", "replace"))`.
   - Responde con `self._json({...})` o con `self._send(200, self._shell(PLANTILLA, "/ruta", "Título", __MARCA__=valor))`.
   - **Audita**: `db.log_event("mi_evento", user=me, origin=self._origin(), ip=self._client_ip(), detail="...")`.
3. **Plantilla** (si es una página): un fragmento en `app/web/` con su `<style>` y su `<script>`. Los valores van por **marcadores** (`__ALGO__`) que reemplaza `_shell`.
   - Escapa todo lo que venga del usuario: `html.escape(...)` en Python y una función `esc()` en JS.
   - Si metes JSON dentro de un `<script>`, haz `.replace("</", "<\\/")` (ver `/gobernanza`).
   - Envuelve el JS de la página en `(function () { ... })();` para no chocar con nombres globales.
4. **Menú** (si toca): `_nav_items`, con su condición de permiso.
5. **Prueba** en `tests/test_web.py` (ver §7): que funciona, que **sin permiso da 403** y que **sin CSRF da 403**.

**Rutas de archivos:** usa siempre `dep_dir()` / `sub_dir()`, que sanean con `os.path.basename`. Nunca construyas rutas con texto del usuario.

---

## 7. Pruebas

```powershell
python -m unittest discover -s tests -v
```

- Cada clase arranca un **Hylanlock real** en un puerto libre, con datos temporales, y lo para al acabar. No toca tu `app/data`.
- La licencia de pruebas se firma con una **clave de pruebas generada en cada ejecución** (`tests/harness.py`). La clave privada de producción no hace falta ni se toca.
- Cubren: login, candados y CSRF; enlace de buzón; aviso de exposición; gobernanza/Supervisor; 2FA completo (activación, login en dos pasos, anti-reutilización, recuperación, política, step-up).
- **Pásalas antes de cada commit.** Si una falla, no subas.

**Añadir una prueba:** copia el esquema de una clase existente:
```python
class TestMiCosa(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inst = Instance(); cls.inst.db()          # BD temporal
        db.create_user("admin", "pass-admin-123", scope="admin")
        cls.inst.start()                              # HYLANLOCK_* como argumentos: start(TRUSTED_PROXIES="...")
    @classmethod
    def tearDownClass(cls):
        cls.inst.stop()
    def test_algo(self):
        c = self.inst.client(); c.login("admin", "pass-admin-123")
        self.assertEqual(c.post_csrf("/admin/mi-cosa", {"x": "1"}, page="/admin")[0], 200)
```

---

## 8. Base de datos

- SQLite en `<DATA_DIR>/hylanlock.db` (modo WAL). Copia consistente: `python app/db.py backup destino.db`.
- **Migraciones:** en `init_db()`, lista de `ALTER TABLE ... ADD COLUMN` idempotentes (si la columna ya existe, se ignora). Para una columna nueva, añádela ahí. **Nunca borres ni renombres columnas.**
- **`meta`**: almacén clave-valor para ajustes de la organización (`db.meta_get` / `db.meta_set`). Lo usan la marca blanca, las extensiones bloqueadas, la política 2FA y el aviso de exposición.
- **Auditoría:** tabla `events` (`db.log_event`). Los tipos de evento son texto libre: usa nombres claros (`user_create`, `2fa_reset`…).
- **CLI útil:**
  ```powershell
  python app/db.py user list
  python app/db.py user reset-2fa <usuario>
  python app/db.py show 50
  ```

---

## 9. Licencias

- La app **solo verifica** (`app/license.py`, clave pública embebida). Firmar es cosa tuya, con `tools/license_gen.py` y la clave privada de `tools/`.
- ⛔ **La clave privada (`tools/hylanlock_license_private.key`) es tu activo más valioso.** Si la pierdes, no puedes emitir licencias; si se filtra, cualquiera puede. **Ten una copia fuera del PC** (USB cifrado o gestor de contraseñas) y no la subas jamás a ningún sitio.
- Ejemplos: `python tools/license_gen.py -c "ACME S.L." -d 14 -o acme` (prueba de 14 días en `acme.txt`) · `-t commercial --expires 2027-01-01 -m 50` (comercial).

---

## 10. Publicar una versión

1. `python -m unittest discover -s tests -v` → todo OK.
2. Commit y push (comandos **separados**, PowerShell no admite `&&`):
   ```powershell
   git add <archivos>
   git commit -m "Qué cambia, en una frase"
   git push
   ```
3. Si cambias la versión visible: `HYLANLOCK_VERSION` (se ve en Ajustes → Acerca de).
4. Paquete para un cliente: `python tools/empaquetar-release.py` → `dist-release/hylanlock-<fecha>.tar.gz` (lista blanca: nunca incluye `tools/`).
5. Instalación en el cliente: `docs/DESPLIEGUE.md` (Docker). HTTPS: `docs/HTTPS.md`.

---

## 11. Variables de configuración (`HYLANLOCK_*`)

| Variable | Para qué |
|---|---|
| `PORT`, `BIND` | Puerto (8000) y dirección de escucha (0.0.0.0) |
| `DATA_DIR` | Carpeta de datos (BD, archivos, licencia) |
| `LAN_CIDR` | Subredes que cuentan como red local (por defecto, todas las privadas). Nunca pongas rangos públicos: la app avisa |
| `TRUSTED_PROXIES` | Proxies de confianza (Caddy) para leer la IP real |
| `TLS_CERT`, `TLS_KEY` | HTTPS integrado sin proxy |
| `BEHIND_TLS` | Pista de que se sirve por HTTPS (cookie Secure + HSTS) |
| `ORG_NAME`, `BRAND_NAME`, `BRAND_LOGO`, `ACCENT` | Nombre de la organización y marca blanca por defecto |
| `ADMIN_USER`, `ADMIN_PASSWORD` | Sembrar el admin en el primer arranque (despliegues automáticos) |
| `SESSION_DAYS`, `STEPUP_MINUTES` | Duración de la sesión y de la elevación |
| `MIN_PASSWORD`, `PW_METHOD`, `ALLOW_DIRECT_PW`, `INVITE_HOURS` | Política de contraseñas e invitaciones |
| `BLOCKED_EXT`, `INCOMPLETE_MAX_MB`, `BUZON_RATE` | Extensiones bloqueadas, tope de subidas a medias, límite del enlace de buzón |
| `LDAP_*` | Active Directory (ver los comentarios en `hylanlock.py`) |
| `TG_TOKEN`, `TG_CHAT` | Avisos por Telegram (opcional) |
| `FEEDBACK_URL`, `VERSION`, `DEV` | Enlace de opinión al acabar la prueba, versión visible, modo desarrollo |

---

## 12. Dónde vive cada funcionalidad reciente

| Funcionalidad | Dónde mirar |
|---|---|
| Enlace de buzón (externos sin cuenta) | `db.create_buzon_link` · rutas `/b/<token>` · `web/buzon.html` |
| HTTPS integrado | `TLS_CERT`/`TLS_KEY` en `main()` · `docs/HTTPS.md` |
| Ajustes y marca blanca | `/ajustes` · `_ajustes_admin_block` · `web/ajustes.html` |
| Aviso de exposición pública | `exposure_note`, `_exposure_banner`, `_exposure_card` |
| Gobernanza (gestionar sin leer) | `governance_snapshot` · `/gobernanza` · `web/gobernanza.html` · rol `supervisor` |
| 2FA | `app/totp.py` · `db.totp_*` · `/login/2fa`, `/perfil/2fa/*` · `web/twofa.html` · step-up en `/elevate` |

---

## 13. Si algo va mal

- **Logs:** la consola del servidor (`docker compose logs -f`). Los avisos llevan `[AVISO]`, `[TLS]`, `[init]`.
- **¿Está vivo?** `GET /healthz` → `ok`.
- **Un admin no puede entrar por el 2FA:** otro admin → Administración → usuario → "Quitar 2FA", o `python app/db.py user reset-2fa <usuario>` en el servidor.
- **Se ha roto una página tras un cambio:** pasa las pruebas; mira la consola del navegador (F12); con `HYLANLOCK_DEV=1`, recarga.
- **Antes de un cambio grande:** copia de la BD (`python app/db.py backup copia.db`).
