#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
📦 Empaqueta el agente en UN SOLO fichero para repartirlo a los equipos.

Produce `dist/hylanlock-agente.pyz`, un ejecutable de Python (formato zipapp, parte de la
biblioteca estándar desde 3.5). Ventajas frente a repartir el `.py` suelto:

  • Es **un archivo**. Se copia a una carpeta y ya está; no hay que explicar qué fichero es cuál.
  • Se ejecuta igual en Windows, Linux y macOS:  `python hylanlock-agente.pyz`
  • Lleva dentro la versión, así que se sabe qué está corriendo cada equipo.

Lo que NO hace, y conviene tenerlo claro antes de prometérselo a un cliente: **esto no es un .exe**.
El equipo necesita Python instalado. Para un ejecutable autónomo de Windows hace falta PyInstaller
sobre una máquina Windows, que es otra herramienta y otra dependencia; ver README.

Uso:
    python3 empaquetar.py
"""

import os
import shutil
import sys
import tempfile
import zipapp

AQUI = os.path.dirname(os.path.abspath(__file__))
ORIGEN = os.path.join(AQUI, "hylanlock_agente.py")
SALIDA = os.path.join(AQUI, "dist", "hylanlock-agente.pyz")

# El intérprete que se pone en la primera línea del paquete. En Linux y macOS permite lanzarlo
# directamente (./hylanlock-agente.pyz); en Windows se ignora y se usa `python fichero.pyz`.
INTERPRETE = "/usr/bin/env python3"


def leer_version():
    """Saca la versión del propio agente, para no tener el número en dos sitios."""
    with open(ORIGEN, "r", encoding="utf-8") as f:
        for linea in f:
            if linea.startswith("VERSION"):
                valor = linea.split("=", 1)[1]
                valor = valor.split("#", 1)[0]          # fuera el comentario de la línea
                return valor.strip().strip('"\'')
    return "desconocida"


def main():
    if not os.path.isfile(ORIGEN):
        print(f"❌ No encuentro {ORIGEN}")
        return 1

    version = leer_version()
    os.makedirs(os.path.dirname(SALIDA), exist_ok=True)

    # zipapp empaqueta una CARPETA cuyo punto de entrada es __main__.py, así que se prepara una
    # temporal. Se usa una carpeta temporal del sistema para no dejar basura en el repositorio.
    with tempfile.TemporaryDirectory() as tmp:
        shutil.copy2(ORIGEN, os.path.join(tmp, "__main__.py"))
        zipapp.create_archive(tmp, target=SALIDA, interpreter=INTERPRETE)

    try:
        os.chmod(SALIDA, 0o755)          # ejecutable: es un programa, no un dato
    except OSError:
        pass

    tam = os.path.getsize(SALIDA)
    print(f"✅ Empaquetado: {SALIDA}")
    print(f"   versión {version} · {tam / 1024:.1f} KB")
    print()
    print("   Probar:   python3 dist/hylanlock-agente.pyz --version")
    print("   Repartir: copia ese único fichero al equipo, junto a instalar-agente.*")
    return 0


if __name__ == "__main__":
    sys.exit(main())
