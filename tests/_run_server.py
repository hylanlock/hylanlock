"""Arranca Hylanlock para las pruebas, aceptando licencias firmadas con la clave de PRUEBAS.

Solo lo usa tests/harness.py. La sustitución de la clave pública ocurre en memoria, en este proceso:
el código del producto no cambia y una instalación real nunca confía en otra clave.
"""
import os
import sys

APP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app")
sys.path.insert(0, APP)
os.chdir(APP)

import license  # noqa: E402

license.LICENSE_PUBLIC_KEY = bytes.fromhex(os.environ["HYLANLOCK_TEST_LICENSE_PUBKEY"])

import hylanlock  # noqa: E402

hylanlock.main()
