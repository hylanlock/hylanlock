# syntax=docker/dockerfile:1
# ─────────────────────────────────────────────────────────────────────────────
# Hylanlock — imagen del producto self-hosted.
# Sin dependencias externas por defecto: solo la biblioteca estándar de Python.
# (LDAP/AD es opcional: --build-arg WITH_LDAP=1.)
# Imagen pequeña, usuario sin privilegios, datos en un volumen (/data).
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HYLANLOCK_PORT=8000 \
    HYLANLOCK_DATA_DIR=/data

# Usuario sin privilegios: NO ejecutar como root. UID fijo para volúmenes/bind-mounts.
RUN useradd --system --uid 10001 --create-home --home-dir /home/app app \
 && mkdir -p /data \
 && chown app:app /data

# ── Soporte OPCIONAL de Active Directory / LDAP ──────────────────────────────
# La imagen por DEFECTO no lleva ninguna dependencia: el núcleo del producto funciona con la
# biblioteca estándar. Una empresa que quiera login con credenciales de dominio construye así:
#     docker compose build --build-arg WITH_LDAP=1
# El código hace import PEREZOSO de ldap3: si no está y AD está apagado, no pasa nada.
ARG WITH_LDAP=0
RUN if [ "$WITH_LDAP" = "1" ]; then pip install --no-cache-dir ldap3==2.9.1; fi

WORKDIR /app
# Copiar solo el código (el .dockerignore excluye datos, temporales y __pycache__).
COPY --chown=app:app app/ /app/

USER app
EXPOSE 8000
VOLUME ["/data"]

# Sonda de salud dedicada: /healthz responde 200 mientras el proceso sirva, sin depender del estado
# de configuración, licencia o red (el primer arranque y el bloqueo por licencia NO deben marcar
# el contenedor como enfermo).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import os,sys,urllib.request; p=os.environ.get('HYLANLOCK_PORT','8000'); sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/healthz'%p, timeout=4).status==200 else 1)"

CMD ["python", "hylanlock.py"]
