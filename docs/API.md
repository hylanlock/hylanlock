# 🔌 API de Hylanlock — v1

API para que otros programas de la empresa **consulten, descarguen y depositen** archivos.

> **Frontera importante**
> - **`/api/v1/*` es el contrato público.** Estable y versionado: puedes construir sobre él.
> - **El resto de `/api/*`** (`/api/departamentos`, `/api/perfil`, `/api/novedades`, `/api/admin/*`)
>   es el backend interno de las pantallas web. **Puede cambiar sin aviso.** No integres contra él.

## Autenticación

Cabecera `Authorization: Bearer <clave>`. Las claves empiezan por `hyl_`.

Una clave pertenece a una **cuenta de servicio**: un principal propio para cada integración, que
**no puede entrar por la web**. La crea el administrador en *Panel → 🔌 Integraciones (API)*.

> ⚠️ La clave se muestra **una sola vez** al emitirla. En el servidor solo queda su hash.
> Si se pierde, se emite otra y se revoca la anterior.

**Por qué una cuenta propia y no el token de un empleado:** si la integración usara la cuenta de una
persona, el día que esa persona cambie de puesto o deje la empresa la integración se rompe —o peor,
su cuenta se queda viva porque «algo la usa». Una integración no es una persona.

## Permisos

Una cuenta de servicio **nace sin acceso a nada**. El administrador le da acceso a carpetas concretas
igual que a un empleado (*Departamentos* y *Subcarpetas*), con estos roles:

| Rol | Puede |
|---|---|
| `reader` | listar y descargar |
| `folder_owner` | listar, descargar (y subir, cuando exista la v2 de escritura) |
| `depositor` | solo dejar archivos — **no aparece en esta API**, porque no puede leer |

Principio de mínimo privilegio: dale solo las carpetas que necesite.

## Límites y red

- **Solo desde la red local**, como el resto del producto. Si una integración concreta debe llamar
  desde fuera, el administrador le concede *acceso remoto* explícitamente (botón en el panel).
- **120 peticiones por minuto y clave** (configurable con `HYLANLOCK_API_RATE`). Al pasarse: `429`.
- Si la **licencia** del servidor caduca, la API se bloquea como el resto del uso.

## Endpoints

### `GET /api/v1/openapi.json`
La especificación **OpenAPI 3.1** de esta API, servida por el propio Hylanlock. Sirve para generar
un cliente, importarla en Postman/Insomnia o mirarla con cualquier visor, **sin salir de la red de
la empresa**. Va protegida igual que el resto de `/api/v1`.

```bash
curl -H "Authorization: Bearer $CLAVE" \
  "http://LA-IP-DE-TU-SERVIDOR:8000/api/v1/openapi.json" -o hylanlock.json
```

Los topes de paginación que aparecen ahí salen de las mismas constantes que usa el servidor, así
que no pueden quedarse desfasados respecto a lo que hace de verdad.

### `GET /api/v1/whoami`
Quién es la clave y qué alcanza. Úsalo para depurar una integración.
```bash
curl -H "Authorization: Bearer $CLAVE" http://LA-IP-DE-TU-SERVIDOR:8000/api/v1/whoami
```
```json
{"user":"erp-facturacion","kind":"service","auth":"token",
 "remote_allowed":false,"folders":["ventas/ana-privado"]}
```

### `GET /api/v1/folders`
Carpetas accesibles: departamentos y subcarpetas.
```json
{"folders":[{"kind":"subfolder","path":"ventas/ana-privado","name":"Ana Privado",
             "department":"Ventas","can_download":true}]}
```

### `GET /api/v1/files?folder=<ruta>`
Archivos de una carpeta. `folder` es `departamento` o `departamento/subcarpeta`.

**Esta respuesta está paginada.** Por defecto devuelve **500** archivos; con `limit` puedes pedir
entre 1 y **1000**. Si quedan más, la respuesta trae `has_more: true` y un `next` que pasas como
`cursor` para seguir.

```bash
curl -H "Authorization: Bearer $CLAVE" \
  "http://LA-IP-DE-TU-SERVIDOR:8000/api/v1/files?folder=ventas/ana-privado&limit=1000"
```
```json
{"folder":"ventas/ana-privado",
 "files":[{"name":"factura.txt","size":30,"mtime":1787666464.0,"sha256":"8ac12c35…"}],
 "has_more":true,
 "next":"WzE3ODc2NjY0NjQuMCwiZmFjdHVyYS50eHQiXQ"}
```

| Parámetro | Qué hace |
|---|---|
| `limit` | Tamaño de página. Por defecto 500, máximo 1000. Fuera de rango se ajusta al tope. |
| `cursor` | El `next` de la respuesta anterior. Un cursor inválido o caducado **no da error**: se empieza por el principio. |

El orden es **fecha descendente** y, a igualdad de fecha, **nombre ascendente**.

> ⚠️ **Comprueba siempre `has_more`.** Si lo ignoras y la carpeta tiene más de 500 archivos, te
> llevarás media carpeta creyendo que la tienes entera. El campo existe precisamente para que un
> cliente que no pagine pueda al menos **darse cuenta**.

> 🔑 El cursor es **opaco**: es la posición del último elemento servido, codificada. No lo
> construyas a mano ni supongas su formato — puede cambiar. Y como se basa en la posición y no en
> un número de página, **borrar archivos mientras paginas no hace que te saltes otros**.

### `GET /api/v1/download?folder=<ruta>&file=<nombre>`
Descarga un archivo. Devuelve la cabecera **`X-Content-SHA256`** para que compruebes la integridad,
y admite descarga por rangos (`Range`).
```bash
curl -H "Authorization: Bearer $CLAVE" -OJ \
  "http://LA-IP-DE-TU-SERVIDOR:8000/api/v1/download?folder=ventas/ana-privado&file=factura.txt"
```

### `GET /api/v1/sync/manifest`
Atajo masivo: todas las carpetas **con sus archivos** en una sola llamada. Lo usa el agente de
sincronización.

Para que una carpeta enorme no convierta esta respuesta en decenas de MB, cada carpeta trae como
mucho **500 archivos**. Si a una le faltan, viene marcada así:

```json
{"user":"ana.lopez","truncated":true,
 "folders":[{"path":"ventas","files":[…],"truncated":true,"next":"WzE3ODc…"}]}
```

- `truncated` (arriba) — a esta respuesta le falta algo por pedir.
- `truncated` + `next` (en una carpeta) — **complétala** con
  `GET /api/v1/files?folder=<path>&cursor=<next>` antes de dar la foto por buena.

> ⚠️ **Si sincronizas borrados, esto es crítico.** Un cliente que trate una respuesta recortada
> como si fuera completa concluirá que los archivos que le faltan han desaparecido del servidor.
> El agente oficial, si no consigue completar una carpeta, **no retira nada en esa pasada**.

### `POST /api/v1/upload?folder=<ruta>&name=<archivo>`
Sube un archivo **en una sola petición**: el cuerpo es el fichero, sin más. (La web usa un
protocolo por trozos porque necesita reanudar en móviles con mala cobertura; una integración no.)

Requiere permiso de **subida** sobre esa carpeta. Devuelve **201**.

```bash
curl -X POST -H "Authorization: Bearer $CLAVE" \
     -H "X-SHA256: $(sha256sum factura.pdf | cut -d' ' -f1)" \
     --data-binary @factura.pdf \
     "http://LA-IP-DE-TU-SERVIDOR:8000/api/v1/upload?folder=ventas/ana-privado&name=factura.pdf"
```
```json
{"name":"factura.pdf","folder":"ventas/ana-privado","size":48213,"sha256":"1086dbb8…"}
```

- **`X-SHA256` (recomendado):** si lo mandas y no coincide con lo que llega, **no se guarda nada**
  y responde `422`. Es la verificación extremo a extremo.
- **Nombre repetido:** no se sobrescribe nunca; el servidor añade un sufijo (`factura (2).pdf`).
- **`name` debe ser un nombre plano**, sin `/` ni `\`. Si mandas una ruta se rechaza con `400` en
  vez de renombrarla en silencio: así no crees haber escrito algo distinto de lo que tienes.
- **Tamaño máximo por petición:** 512 MB (`HYLANLOCK_API_MAX_UPLOAD_MB`).
- El archivo se escribe **a disco a trozos** y se mueve de forma atómica al terminar: nunca queda
  un fichero a medias con el nombre bueno.

> 💡 **El patrón que más se usa:** una integración con rol `depositor` sobre una carpeta puede
> **dejar** archivos pero **no ver** los que hay. Un ERP que deposita facturas en la carpeta de
> alguien sin poder leer su contenido — el buzón de entrega, por API.

## Errores

Formato uniforme:
```json
{"error": "forbidden", "detail": "Esta clave no puede listar esa carpeta."}
```

| HTTP | `error` | Cuándo |
|---|---|---|
| 400 | `bad_request` | Falta un parámetro o no tiene forma válida |
| 401 | — | Clave ausente, mal escrita o **revocada** |
| 403 | `forbidden` | La clave no tiene permiso sobre esa carpeta |
| 403 | — | Llamada **desde fuera de la red local** (sin acceso remoto concedido) |
| 404 | `not_found` | Ese archivo no está en esa carpeta |
| 413 | `too_large` | El archivo supera el máximo por petición |
| 422 | `hash_mismatch` | El `X-SHA256` no coincide — **no se guardó nada** |
| 429 | `rate_limited` | Has superado el límite por minuto |

> Listar una carpeta a la que no tienes acceso devuelve **403 exista o no**: la API no revela qué
> carpetas hay en el servidor.

## Ejemplo completo (Python, solo biblioteca estándar)

```python
import json, urllib.request

BASE, CLAVE = "http://LA-IP-DE-TU-SERVIDOR:8000", "hyl_…"

def get(ruta):
    req = urllib.request.Request(BASE + ruta)
    req.add_header("Authorization", "Bearer " + CLAVE)
    return urllib.request.urlopen(req, timeout=30)

for c in json.load(get("/api/v1/folders"))["folders"]:
    cursor = ""
    while True:                       # la carpeta puede no caber en una sola respuesta
        ruta = f"/api/v1/files?folder={c['path']}&limit=1000"
        if cursor:
            ruta += f"&cursor={cursor}"
        datos = json.load(get(ruta))
        for f in datos["files"]:
            print(c["path"], f["name"], f["sha256"][:12])
        cursor = datos.get("next")
        if not cursor:
            break
```

## Seguridad de la escritura

La API es la **única** vía de escritura con clave: un `POST` con token a cualquier ruta que no sea
`/api/v1/*` se rechaza. Y la exención de CSRF que hace posible escribir por API se aplica **solo si
la petición NO trae una sesión de cookie válida**: una petición con la cookie de un usuario más una
cabecera `Authorization` **no** queda exenta. Es la regla que impide convertir la API en un rodeo
para el CSRF.

## Pendiente

- **Webhooks salientes** (avisar a otra app cuando llega un archivo).
- **Borrado** por API: no existe, y es deliberado — la regla del producto es que los datos no se
  destruyen desde fuera.
