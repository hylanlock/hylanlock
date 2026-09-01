# 🔄 Agente de sincronización de Hylanlock

Trae a una carpeta de tu ordenador **todo lo que puedes ver en Hylanlock**: tus departamentos y
tus carpetas personales. Lo dejas puesto y se mantiene al día solo.

> **Qué hace y qué NO hace**
> - ✅ **Solo baja.** Nunca sube nada ni borra nada del servidor.
> - ✅ **Nunca borra en tu ordenador.** Lo que se retira del servidor se aparta a una papelera
>   (`_retirados/`), y lo que hayas modificado tú no se toca. Ver *Qué pasa cuando algo se retira*.
> - ✅ **Solo copia.** Deja los ficheros en una carpeta. **Nunca los abre ni los ejecuta** — hacerlo
>   convertiría la carpeta compartida en una vía de entrada de malware.
> - ✅ **Solo dentro de la red local** de la empresa, como el resto de Hylanlock.
> - ✅ **Incremental**: compara el SHA-256 y solo se trae lo que ha cambiado.
> - ✅ **Verifica** cada descarga: si el hash no coincide, descarta el fichero y avisa.

## Qué necesitas
- **Python 3** (no hace falta instalar nada más: solo biblioteca estándar).
- Un **token de equipo**, que sacas tú mismo de la web.

## Instalación rápida (lo normal)

Si tu administrador te ha pasado una carpeta con `hylanlock-agente.pyz` y un instalador:

**Windows** — doble clic en `instalar-agente.bat`.
**Linux** — `./instalar-agente.sh` en un terminal.

El instalador deja el agente puesto para que arranque solo al iniciar sesión y te crea la
configuración. Solo te queda abrirla y pegar **tu token** (paso 1 de abajo). Para quitarlo:
`instalar-agente.bat /quitar` o `./instalar-agente.sh --desinstalar`; ninguno de los dos toca tus
archivos ni tu configuración.

> Los dos instaladores trabajan **en tu usuario**, no en el sistema: no piden administrador y
> sincronizan con tus permisos, no con los de la máquina.

## Puesta en marcha a mano (3 pasos)

**1. Saca tu token.** En Hylanlock → **👤 Mi perfil** → *💻 Equipos sincronizados*. Ponle un nombre
que reconozcas ("Portátil de la oficina") y pulsa *Dar de alta*.

> ⚠️ El token se enseña **una sola vez**. Cópialo en ese momento. Si lo pierdes, no pasa nada:
> revocas ese y das de alta otro.

**2. Crea la configuración.**
```bash
python3 hylanlock_agente.py --init
```
Se crea `hylanlock_agente.json`. Ábrelo y rellena:
```json
{
  "servidor": "http://LA-IP-DE-TU-SERVIDOR:8000",
  "token": "hyl_…el token que copiaste…",
  "destino": "~/Hylanlock"
}
```

**3. Sincroniza.**
```bash
python3 hylanlock_agente.py            # una pasada y sale
python3 hylanlock_agente.py --cada 300 # se queda en marcha, cada 5 minutos
python3 hylanlock_agente.py --simular  # dice qué haría, sin escribir nada
```

Los archivos aparecen en `destino/<departamento>/` y `destino/<departamento>/<subcarpeta>/`.

## Qué pasa cuando algo se retira del servidor

Si un fichero se borra en el servidor —o si te **revocan el acceso** a una carpeta— tu copia local
deja de tener sentido: apunta a algo que ya no deberías tener a mano. El agente se encarga, pero
con cuidado y **sin destruir nada**:

- El fichero **se aparta** a `destino/_retirados/AAAA-MM-DD/`, conservando la carpeta de la que
  venía. No se borra. Si fue un error de permisos, lo tienes ahí.
- **Si tú lo habías modificado, no se toca.** El agente compara la huella del fichero con la que
  tenía cuando lo bajó: si no coincide, ese fichero ha pasado a ser trabajo tuyo y se queda donde
  está. Te lo dice con un `✋` en el registro.
- **Lo que hayas puesto tú en esa carpeta nunca se mira.** El agente solo considera los ficheros
  que bajó él, que anota en `destino/.hylanlock-agente-estado.json`.
- Si el manifiesto llega incompleto o ese registro está ilegible, **no se retira nada** en esa
  pasada. Ante la duda, se queda de más.

`--simular` te dice exactamente qué apartaría, sin tocar nada.

> 🧹 La papelera **no se vacía sola**: es tuya, la borras cuando quieras.

## Para el administrador: preparar el reparto

El agente se distribuye como **un solo fichero**, `hylanlock-agente.pyz`. Se genera así:

```bash
python3 empaquetar.py        # -> dist/hylanlock-agente.pyz
```

Es un *zipapp*: formato de la biblioteca estándar de Python, sin herramientas externas ni
dependencias. Se ejecuta igual en Windows, Linux y macOS con `python hylanlock-agente.pyz`, y
lleva la versión dentro (`--version`), que es lo que preguntarás cuando alguien reporte un fallo.

Para repartirlo, copia a cada equipo esa carpeta con tres ficheros:

```
hylanlock-agente.pyz     el agente
instalar-agente.bat      instalador de Windows
instalar-agente.sh       instalador de Linux
```

> ⚠️ **Esto no es un `.exe`: el equipo necesita Python instalado.** Para la mayoría de parques
> Windows eso es un obstáculo real. Un ejecutable autónomo se puede generar con **PyInstaller**
> sobre una máquina Windows, pero es otra herramienta, añade dependencias y hay que firmarlo para
> que el antivirus no lo marque. Está pendiente de decidir.

## Que arranque solo con el equipo (a mano)

**Windows** — Programador de tareas: nueva tarea, *Al iniciar sesión*, acción
`pythonw.exe` con argumentos `C:\ruta\hylanlock_agente.py --cada 300`
(`pythonw` en vez de `python` para que no deje una ventana negra abierta).

**Linux** — `~/.config/systemd/user/hylanlock-agente.service`:
```ini
[Unit]
Description=Agente de sincronización de Hylanlock
[Service]
ExecStart=/usr/bin/python3 %h/hylanlock/hylanlock_agente.py --cada 300 -c %h/hylanlock/hylanlock_agente.json
Restart=on-failure
[Install]
WantedBy=default.target
```
```bash
systemctl --user enable --now hylanlock-agente
```

## Si algo no va

| Mensaje | Qué significa |
|---|---|
| `El servidor rechaza el token (401)` | Lo has revocado, ha caducado tu cuenta, o está mal copiado. Da de alta otro. |
| `Prohibido (403)` | Estás **fuera de la red local**. El agente solo funciona en la oficina. |
| `No consigo hablar con el servidor` | Servidor apagado, o la URL de `servidor` no es la correcta. |
| `el SHA-256 no coincide` | El fichero llegó corrupto o alterado: se descarta. Se reintenta en la pasada siguiente. |
| `ya no está en el servidor, pero lo has modificado` | Tu copia difiere de la que se bajó: se conserva y sale del control del agente. Si quieres que vuelva a sincronizarse, bórrala y déjale bajarla otra vez. |
| `el servidor no te ofrece ninguna carpeta` | Te han revocado los accesos, o el usuario está desactivado. Tus ficheros están en `_retirados/`. |
| `No hay nada que sincronizar` | No tienes carpetas con permiso de **ver y descargar**. Si solo tienes un *buzón de entrega* (puedes dejar pero no ver), es normal: ahí no hay nada que traerse. |

## Seguridad

- El token vive en `hylanlock_agente.json`, que se crea con permisos `600` (solo tu usuario).
  Trátalo como una contraseña.
- El agente **hereda tus permisos**, ni uno más. No puede ver nada que no vieras tú en la web.
- Los ficheros se guardan sin permiso de ejecución (`600`).
- Revocar un equipo en tu perfil corta su sincronización **al instante**.
- Al revocar el acceso de alguien a una carpeta, su copia local se aparta en la siguiente pasada
  del agente. Ten en cuenta que **es una papelera, no un borrado**: si necesitas que el fichero
  desaparezca de verdad de ese equipo, hay que vaciarla.
