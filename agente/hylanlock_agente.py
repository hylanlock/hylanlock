#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🔄 Hylanlock — Agente de sincronización (servidor → PC)

Trae a una carpeta local todo lo que el usuario puede ver en el servidor: sus departamentos y
sus subcarpetas. Pensado para arrancar con el equipo (Task Scheduler en Windows, systemd o la
carpeta de Inicio en Linux) y quedarse al día solo.

Principios (no negociables):
  • SOLO BAJA. Nunca sube, nunca borra nada del servidor.
  • NUNCA DESTRUYE EN LOCAL. Lo que se retira del servidor se APARTA a una papelera
    ('_retirados/AAAA-MM-DD/'), nunca se borra. Y solo se aparta lo que bajó el propio agente y
    sigue igual que cuando lo bajó: si el usuario lo ha modificado, es suyo y no se toca.
  • COPIA, NUNCA EJECUTA. Deja ficheros en una carpeta y punto. Jamás abre ni lanza lo que llega:
    sería un vector de malware perfecto.
  • Se autentica con un TOKEN DE DISPOSITIVO (no con la contraseña del usuario). El token se
    genera desde "Mi perfil" en la web y es revocable por separado.
  • Solo funciona dentro de la RED LOCAL, como el resto del producto.

Sin dependencias: solo biblioteca estándar de Python 3.

Uso:
    python3 hylanlock_agente.py --init          # crea un fichero de configuración de ejemplo
    python3 hylanlock_agente.py                 # sincroniza una vez y sale
    python3 hylanlock_agente.py --cada 300      # sincroniza cada 300 s (se queda en marcha)
    python3 hylanlock_agente.py --simular       # dice qué haría, sin escribir nada
"""

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "1.2"                            # sube al cambiar el agente; se ve con --version
CONFIG_POR_DEFECTO = "hylanlock_agente.json"
ESTADO = ".hylanlock-agente-estado.json"   # qué bajó el agente, para saber qué es suyo
PAPELERA = "_retirados"                    # donde se aparta lo que ya no está en el servidor
TIEMPO_ESPERA = 30          # segundos de espera por petición
TROZO = 1024 * 256          # 256 KB por lectura al descargar


# --------------------------------------------------------------------------- utilidades
# En Windows la consola suele ser cp1252 y no sabe imprimir emojis (✅/⚠️): sin esto, un mensaje
# con un emoji hacía CAER al agente con UnicodeEncodeError. Reconfiguramos la salida a UTF-8 con
# reemplazo. Con pythonw (arranque automático, sin ventana) sys.stdout puede ser None: se ignora.
for _flujo in (sys.stdout, sys.stderr):
    try:
        _flujo.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def log(msg):
    linea = f"[{time.strftime('%H:%M:%S')}] {msg}"
    try:
        print(linea, flush=True)
    except Exception:
        # Consola que no admite el carácter, o sin salida (pythonw): degradar a ASCII sin romper.
        # log() JAMÁS debe tumbar al agente.
        try:
            print(linea.encode("ascii", "replace").decode("ascii"), flush=True)
        except Exception:
            pass


def sha256_fichero(ruta):
    """SHA-256 de un fichero local, leyendo a trozos (no carga el fichero entero en memoria)."""
    h = hashlib.sha256()
    try:
        with open(ruta, "rb") as f:
            for bloque in iter(lambda: f.read(TROZO), b""):
                h.update(bloque)
    except OSError:
        return None
    return h.hexdigest()


def nombre_seguro(nombre):
    """Sanea un nombre que viene del SERVIDOR antes de usarlo como fichero local.

    No se confía en él aunque sea nuestro propio servidor: si alguien lo comprometiera, un nombre
    como '../../.bashrc' escribiría fuera de la carpeta destino. Nos quedamos solo con el nombre.
    """
    nombre = (nombre or "").replace("\\", "/")
    nombre = os.path.basename(nombre)
    if nombre in ("", ".", ".."):
        return ""
    return nombre


def carpeta_segura(base, relativa):
    """Une base + ruta relativa comprobando que el resultado NO se sale de 'base'."""
    partes = [nombre_seguro(p) for p in (relativa or "").split("/") if p]
    if not all(partes):
        return ""
    destino = os.path.join(base, *partes)
    if os.path.commonpath([os.path.realpath(base),
                           os.path.realpath(os.path.dirname(destino) or base)]) \
            != os.path.realpath(base):
        return ""
    return destino


# --------------------------------------------------------------------------- estado local
# El agente apunta qué ficheros ha bajado él y con qué SHA-256. Sin esta lista no podría
# distinguir SUS ficheros de los que el usuario haya dejado en la misma carpeta, y "sincronizar
# los borrados" acabaría llevándose por delante trabajo ajeno.

def ruta_estado(destino):
    return os.path.join(destino, ESTADO)


def entrada_estado(valor):
    """Normaliza una entrada del registro. Acepta el formato antiguo (solo el hash en un texto)
    para no obligar a rebajarse todo si se actualiza el agente."""
    if isinstance(valor, str):
        return {"sha256": valor, "size": None, "mtime": None}
    if isinstance(valor, dict):
        return {"sha256": valor.get("sha256") or "",
                "size": valor.get("size"), "mtime": valor.get("mtime")}
    return {"sha256": "", "size": None, "mtime": None}


def cargar_estado(destino):
    """Devuelve {ruta_relativa: {sha256, size, mtime}} de lo que bajó el agente.

    Ante la duda, vacío: un registro ilegible debe hacernos NO retirar nada, nunca de más."""
    try:
        with open(ruta_estado(destino), "r", encoding="utf-8") as f:
            datos = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        log("   ⚠️  el registro del agente está ilegible; esta vez no retiro nada.")
        return None
    if not isinstance(datos, dict):
        return None
    archivos = datos.get("archivos")
    if not isinstance(archivos, dict):
        return None
    return {k: entrada_estado(v) for k, v in archivos.items()}


def guardar_estado(destino, archivos):
    """Escribe el registro de forma atómica: o queda el nuevo entero, o se queda el anterior."""
    tmp = ruta_estado(destino) + ".part"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"version": 2, "archivos": archivos}, f, indent=2, ensure_ascii=False)
        os.replace(tmp, ruta_estado(destino))
        os.chmod(ruta_estado(destino), 0o600)
    except OSError as e:
        log(f"   ⚠️  no pude guardar el registro del agente: {e}")


def apartar(destino, clave, ruta_local):
    """Mueve un fichero retirado a la papelera, conservando su ruta original dentro.

    Nunca borra: si algo sale mal, el fichero se queda donde estaba.
    """
    partes = [nombre_seguro(x) for x in clave.split("/") if x]
    if not partes:
        return False
    carpeta = os.path.join(destino, PAPELERA, time.strftime("%Y-%m-%d"), *partes[:-1])
    try:
        os.makedirs(carpeta, exist_ok=True)
    except OSError as e:
        log(f"   ⚠️  no pude preparar la papelera: {e}")
        return False

    objetivo = os.path.join(carpeta, partes[-1])
    # Si ya apartamos otro con el mismo nombre hoy, no lo pisamos.
    if os.path.exists(objetivo):
        raiz, ext = os.path.splitext(objetivo)
        objetivo = f"{raiz}-{time.strftime('%H%M%S')}{ext}"
    try:
        os.replace(ruta_local, objetivo)
    except OSError as e:
        log(f"   ⚠️  no pude apartar {clave}: {e}")
        return False
    return True


def retirar_desaparecidos(destino, previos, vistos, simular):
    """Aparta lo que el agente bajó en su día y ya no está disponible en el servidor.

    Motivos por los que algo deja de estar: se borró en el servidor, o al usuario le han
    revocado el acceso a esa carpeta. En los dos casos la copia local debe dejar de estar a mano.

    Reglas de seguridad, por orden:
      • Solo se mira lo que figura en NUESTRO registro. Lo que el usuario haya puesto ahí por su
        cuenta no se toca jamás, ni se mira.
      • Si el fichero ya no coincide con el SHA-256 con el que lo bajamos, el usuario lo ha
        modificado: pasa a ser suyo. Se conserva y se saca del registro.
      • Nada se borra: se aparta a la papelera.
    """
    retirados = conservados = 0
    for clave, entrada in previos.items():
        if clave in vistos:
            continue                      # sigue disponible en el servidor
        ruta_local = carpeta_segura(destino, clave)
        if not ruta_local or not os.path.isfile(ruta_local):
            continue                      # ya no está en local: no hay nada que hacer
        sha_bajado = entrada.get("sha256")
        # Sin hash de referencia no podemos demostrar que el fichero siga siendo el nuestro,
        # así que no lo tocamos: preferimos dejar de más antes que apartar trabajo del usuario.
        if not sha_bajado:
            conservados += 1
            continue
        if sha256_fichero(ruta_local) != sha_bajado:
            log(f"   ✋ {clave}: ya no está en el servidor, pero lo has modificado. Lo dejo.")
            conservados += 1
            continue
        if simular:
            log(f"   (simulado) apartaría {clave}")
            retirados += 1
            continue
        if apartar(destino, clave, ruta_local):
            log(f"   🗑️  {clave} → {PAPELERA}/")
            retirados += 1
    return retirados, conservados


# --------------------------------------------------------------------------- configuración
def cargar_config(ruta):
    try:
        with open(ruta, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except FileNotFoundError:
        log(f"❌ No encuentro la configuración: {ruta}")
        log("   Crea una con:  python3 hylanlock_agente.py --init")
        return None
    except (OSError, ValueError) as e:
        log(f"❌ Configuración ilegible ({e})")
        return None
    for clave in ("servidor", "token", "destino"):
        if not cfg.get(clave):
            log(f"❌ Falta '{clave}' en la configuración.")
            return None
    # Plantilla sin rellenar: parar AQUÍ. Si se dejara pasar, el agente mandaría el token a
    # cualquier equipo que ocupara esa dirección en la red del cliente.
    for clave, marcador in (("servidor", "LA-IP-DE-TU-SERVIDOR"),
                            ("token", "pega-aqui-el-token")):
        if marcador in str(cfg.get(clave, "")):
            log(f"❌ El campo '{clave}' de {ruta} sigue con el texto de ejemplo.")
            log("   Edita la configuración: pon la dirección de TU servidor y TU token")
            log("   (lo generas en la web, en 'Mi perfil' → Equipos sincronizados).")
            return None
    cfg["servidor"] = cfg["servidor"].rstrip("/")
    cfg["destino"] = os.path.expanduser(cfg["destino"])
    return cfg


def escribir_ejemplo(ruta):
    if os.path.exists(ruta):
        log(f"⚠️  Ya existe {ruta}; no lo toco.")
        return False
    ejemplo = {
        # Marcadores de posición A PROPÓSITO. Antes aquí había una IP real de ejemplo, y eso es
        # peligroso: quien no la cambiara mandaría su token —una credencial— a la máquina que
        # hubiera en esa dirección de SU red. El agente se niega a arrancar hasta que se cambien.
        "servidor": "http://LA-IP-DE-TU-SERVIDOR:8000",
        "token": "pega-aqui-el-token-de-tu-perfil",
        "destino": "~/Hylanlock",
    }
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(ejemplo, f, indent=2, ensure_ascii=False)
    try:
        os.chmod(ruta, 0o600)      # el token es una credencial: que no lo lean otros usuarios
    except OSError:
        pass
    log(f"✅ Creada {ruta}. Edítala: pon la URL de tu servidor, tu token y dónde quieres los archivos.")
    log("   El token se genera en la web, en 'Mi perfil' → Equipos sincronizados.")
    return True


# --------------------------------------------------------------------------- red
def peticion(cfg, ruta, cabeceras=None):
    url = cfg["servidor"] + ruta
    req = urllib.request.Request(url)
    req.add_header("Authorization", "Bearer " + cfg["token"])
    for k, v in (cabeceras or {}).items():
        req.add_header(k, v)
    return urllib.request.urlopen(req, timeout=TIEMPO_ESPERA)


def obtener_manifiesto(cfg):
    """Pide al servidor TODO lo que este usuario puede traerse, en una sola llamada."""
    try:
        with peticion(cfg, "/api/v1/sync/manifest") as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 401:
            log("❌ El servidor rechaza el token (401). ¿Lo has revocado, o está mal copiado?")
        elif e.code == 403:
            log("❌ Prohibido (403). El agente solo funciona desde la RED LOCAL de la empresa.")
        else:
            log(f"❌ El servidor responde {e.code}.")
    except urllib.error.URLError as e:
        log(f"❌ No consigo hablar con el servidor: {e.reason}")
    except ValueError:
        log("❌ El servidor ha contestado algo que no es JSON.")
    return None


def completar_carpeta(cfg, ruta, cursor):
    """Trae el resto de ficheros de una carpeta que el manifiesto devolvió RECORTADA.

    El manifiesto trae como mucho unos cientos de ficheros por carpeta para no convertirse en una
    respuesta gigante. Si una carpeta viene marcada como recortada, hay que completarla ANTES de
    decidir qué se retira: con una foto a medias, el agente creería que los ficheros que faltan
    han desaparecido del servidor y los apartaría. Por eso, si esto falla, la pasada se marca como
    incompleta y no se retira nada.

    Devuelve la lista de ficheros que faltaban, o None si no se pudo completar.
    """
    resto = []
    vueltas = 0
    while cursor:
        vueltas += 1
        if vueltas > 200:                     # cinturón: 200 páginas de 1000 = 200.000 ficheros
            log(f"   ⚠️  {ruta}: demasiadas páginas; no completo la lista.")
            return None
        # Se pide la página MÁS GRANDE que admite el servidor: cada página es una petición, y la
        # API tiene un límite por minuto. Con páginas pequeñas, completar una carpeta enorme se
        # comería esa cuota y acabaría en 429.
        url = ("/api/v1/files?folder=" + urllib.parse.quote(ruta)
               + "&limit=1000&cursor=" + urllib.parse.quote(cursor))
        try:
            with peticion(cfg, url) as r:
                datos = json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 429:
                log(f"   ⚠️  {ruta}: el servidor pide calma (429). Lo dejo para la pasada siguiente.")
            else:
                log(f"   ⚠️  {ruta}: no pude completar el listado (HTTP {e.code}).")
            return None
        except (urllib.error.URLError, OSError, ValueError) as e:
            log(f"   ⚠️  {ruta}: no pude completar el listado ({e}).")
            return None
        resto.extend(datos.get("files", []))
        cursor = datos.get("next")
    return resto


def descargar(cfg, url_base, nombre, destino, esperado, simular):
    """Baja un fichero a 'destino'. Escribe primero en .part y renombra al final, para que nunca
    quede un fichero a medias con el nombre bueno. Verifica el SHA-256 antes de dar por buena
    la descarga: si no cuadra, se tira.

    Devuelve el SHA-256 de lo que ha quedado en disco, o None si no pudo. Lo devuelve SIEMPRE,
    aunque el servidor no nos diera un hash esperado: es lo que permite al agente reconocer más
    tarde si ese fichero sigue siendo el que él dejó o el usuario lo ha tocado.
    """
    if simular:
        log(f"   (simulado) bajaría {nombre}")
        return ""
    ruta = url_base + "?file=" + urllib.parse.quote(nombre)
    parcial = destino + ".part"
    try:
        with peticion(cfg, ruta) as r, open(parcial, "wb") as f:
            h = hashlib.sha256()
            while True:
                bloque = r.read(TROZO)
                if not bloque:
                    break
                f.write(bloque)
                h.update(bloque)
        obtenido = h.hexdigest()
    except (urllib.error.HTTPError, urllib.error.URLError, OSError) as e:
        log(f"   ⚠️  no pude bajar {nombre}: {e}")
        try:
            os.remove(parcial)
        except OSError:
            pass
        return None

    if esperado and obtenido != esperado:
        log(f"   ⚠️  {nombre}: el SHA-256 no coincide. Descartado (llegó corrupto o alterado).")
        try:
            os.remove(parcial)
        except OSError:
            pass
        return None
    try:
        os.replace(parcial, destino)     # atómico: o está entero o no está
        os.chmod(destino, 0o600)         # nunca ejecutable: esto son datos, no programas
    except OSError as e:
        log(f"   ⚠️  no pude guardar {nombre}: {e}")
        return None
    return obtenido


# --------------------------------------------------------------------------- sincronización
def sincronizar(cfg, simular=False):
    man = obtener_manifiesto(cfg)
    if man is None:
        return False

    destino = cfg["destino"]
    carpetas = man.get("folders", [])
    log(f"👤 {man.get('user', '?')} · {len(carpetas)} carpeta(s) disponibles")

    # Lo que bajamos en su día. None = registro ilegible -> esta vez no retiramos nada.
    previos = cargar_estado(destino)

    # 'vistos' es la foto de lo que el servidor ofrece AHORA. Se rellena leyendo el manifiesto,
    # nunca a partir de si la descarga salió bien: un fallo de red no significa que el fichero
    # haya desaparecido del servidor, y retirarlo por eso sería un error grave.
    vistos = {}       # claves disponibles hoy en el servidor (para saber qué NO retirar)
    indice = {}       # {ruta_relativa: sha256 real del fichero local} -> es lo que se guarda
    # Si nos saltamos una carpeta por seguridad, no tenemos la foto completa y no se retira nada:
    # más vale quedarse con archivos de más que apartar algo que sí estaba disponible.
    foto_completa = True
    nuevos = iguales = fallos = 0

    for c in carpetas:
        ruta_carpeta = c.get("path", "")
        destino_carpeta = carpeta_segura(destino, ruta_carpeta)
        if not destino_carpeta:
            log(f"   ⚠️  ruta sospechosa en el manifiesto: {ruta_carpeta!r} — la salto")
            foto_completa = False
            continue

        partes = [nombre_seguro(x) for x in ruta_carpeta.split("/") if x]
        ficheros = c.get("files", [])

        # Carpeta con más ficheros de los que cabe en el manifiesto: hay que completarla antes de
        # seguir. Sin esto la foto quedaría a medias y la retirada apartaría ficheros que sí están.
        if c.get("truncated"):
            log(f"   … {ruta_carpeta}: el servidor la ha recortado, pido el resto")
            resto = completar_carpeta(cfg, ruta_carpeta, c.get("next"))
            if resto is None:
                foto_completa = False
            else:
                ficheros = ficheros + resto
                log(f"   … {ruta_carpeta}: {len(ficheros)} fichero(s) en total")

        # Primero se anota TODO lo que el servidor dice tener aquí. Da igual si luego falla la
        # descarga: lo que importa para no retirarlo es que sigue estando disponible.
        for f in ficheros:
            nombre = nombre_seguro(f.get("name"))
            if nombre:
                vistos["/".join(partes + [nombre])] = True

        if not simular:
            try:
                os.makedirs(destino_carpeta, exist_ok=True)
            except OSError as e:
                log(f"   ⚠️  no pude crear {destino_carpeta}: {e}")
                continue
        log(f"📁 {ruta_carpeta}  ({len(ficheros)} fichero(s))")

        for f in ficheros:
            nombre = nombre_seguro(f.get("name"))
            if not nombre:
                continue
            clave = "/".join(partes + [nombre])
            ruta_local = os.path.join(destino_carpeta, nombre)
            esperado = f.get("sha256")
            anterior = (previos or {}).get(clave)

            # ── ¿Hace falta bajarlo otra vez? ──────────────────────────────────────────────
            # Caso bueno: el servidor nos da su SHA-256 (lo hace con todo lo que se sube por la
            # web o la API). Comparamos y listo.
            if esperado and os.path.isfile(ruta_local) and sha256_fichero(ruta_local) == esperado:
                iguales += 1
                indice[clave] = {"sha256": esperado, "size": f.get("size"),
                                 "mtime": f.get("mtime")}
                continue

            # Caso sin hash: pasa con los ficheros que un administrador deja directamente en la
            # carpeta del servidor, que no llevan el .sha256 al lado. Antes esto obligaba a
            # rebajarlos ENTEROS en cada pasada, para siempre. Ahora nos apoyamos en nuestro
            # registro: si el servidor sigue anunciando el mismo tamaño y la misma fecha, y
            # nuestra copia sigue siendo la que bajamos, no hay nada que traer.
            if (not esperado and anterior and anterior.get("sha256")
                    and anterior.get("size") == f.get("size")
                    and anterior.get("mtime") == f.get("mtime")
                    and os.path.isfile(ruta_local)
                    and sha256_fichero(ruta_local) == anterior["sha256"]):
                iguales += 1
                indice[clave] = anterior
                continue

            # A punto de sobrescribir. Si ya hay una copia local y NO es la que bajamos
            # nosotros, el usuario la ha tocado: se aparta a la papelera antes de pisarla.
            # El agente promete no destruir nada en local, y esto era el único sitio donde sí
            # lo hacía: el fichero que el servidor BORRA se conserva con mimo, pero el que el
            # usuario EDITA se perdía sin decir nada.
            if (anterior and anterior.get("sha256") and os.path.isfile(ruta_local)
                    and sha256_fichero(ruta_local) != anterior["sha256"]):
                if simular:
                    log(f"   (simulado) apartaría tu versión modificada de {nombre}")
                elif apartar(destino, clave, ruta_local):
                    log(f"   ✋ tu versión de {nombre} estaba modificada → {PAPELERA}/")

            obtenido = descargar(cfg, c.get("download_url", ""), nombre, ruta_local, esperado,
                                 simular)
            if obtenido is not None:
                nuevos += 1
                if obtenido:
                    indice[clave] = {"sha256": obtenido, "size": f.get("size"),
                                     "mtime": f.get("mtime")}
                log(f"   ⬇️  {nombre}")
            else:
                fallos += 1

    # ── Retirar lo que ya no está disponible ────────────────────────────────────────────────
    retirados = conservados = 0
    if previos is None:
        pass                                  # registro ilegible: ya se avisó al cargarlo
    elif not foto_completa:
        log("   ⚠️  el manifiesto venía incompleto; no retiro nada en esta pasada.")
    elif previos:
        if not carpetas:
            log("   ⚠️  el servidor no te ofrece ninguna carpeta. Si antes tenías acceso, "
                "aparto tu copia local (la tendrás en la papelera).")
        retirados, conservados = retirar_desaparecidos(destino, previos, vistos, simular)

    # El registro se queda con la foto actual: lo que el servidor ofrece hoy. Lo que el usuario
    # haya modificado se cae solo de la lista, porque ha dejado de ser nuestro.
    if not simular:
        guardar_estado(destino, indice)

    if not carpetas and not retirados:
        log("   No hay nada que sincronizar. (Si esperabas archivos, pide acceso a tu administrador.)")

    resumen = f"✅ Listo: {nuevos} nuevo(s), {iguales} ya al día"
    if retirados:
        resumen += f", {retirados} retirado(s) a {PAPELERA}/"
    if conservados:
        resumen += f", {conservados} conservado(s) por estar modificado(s)"
    if fallos:
        resumen += f", {fallos} con problemas"
    log(resumen)
    return fallos == 0


def main():
    ap = argparse.ArgumentParser(description="Agente de sincronización de Hylanlock (solo bajada).")
    ap.add_argument("-c", "--config", default=CONFIG_POR_DEFECTO, help="fichero de configuración")
    ap.add_argument("--init", action="store_true", help="crear una configuración de ejemplo")
    ap.add_argument("--cada", type=int, metavar="SEG",
                    help="repetir cada SEG segundos en vez de una sola pasada")
    ap.add_argument("--simular", action="store_true", help="decir qué haría, sin escribir nada")
    ap.add_argument("--version", action="version", version=f"Agente de Hylanlock {VERSION}")
    args = ap.parse_args()

    if args.init:
        return 0 if escribir_ejemplo(args.config) else 1

    cfg = cargar_config(args.config)
    if not cfg:
        return 1

    log(f"🔄 Hylanlock {VERSION} · sincronizando desde {cfg['servidor']} hacia {cfg['destino']}")
    if args.simular:
        log("   (modo simulación: no se escribe nada)")

    if not args.cada:
        return 0 if sincronizar(cfg, args.simular) else 1

    espera = max(30, args.cada)      # no machacar el servidor
    log(f"   repitiendo cada {espera} s · Ctrl+C para parar")
    while True:
        try:
            sincronizar(cfg, args.simular)
        except Exception as e:                      # el agente NUNCA debe morirse solo
            log(f"⚠️  error inesperado: {e}")
        try:
            time.sleep(espera)
        except KeyboardInterrupt:
            log("👋 parado.")
            return 0


if __name__ == "__main__":
    sys.exit(main())
