#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
# Instalador de Hylanlock (Linux) — un solo comando.
#
#   curl -fsSL https://raw.githubusercontent.com/hylanlock/hylanlock/main/instalar.sh | sudo sh
#
# Qué hace:
#   1) Instala Docker si no está.
#   2) Descarga Hylanlock (git si está disponible; si no, un .tar.gz).
#   3) Lo construye y lo arranca.
#   4) Te dice la dirección para abrir en el navegador.
#
# No pide más datos: usa los valores por defecto (el .env es opcional). Para personalizar
# después, edita el .env dentro de la carpeta 'hylanlock' y vuelve a  docker compose up -d --build.
# ─────────────────────────────────────────────────────────────────────────────
set -e

DIR="${HYLANLOCK_DIR:-hylanlock}"
REPO="https://github.com/hylanlock/hylanlock.git"
TARBALL="https://github.com/hylanlock/hylanlock/archive/refs/heads/main.tar.gz"

echo "======================================"
echo "  Instalación de Hylanlock"
echo "======================================"

# 1) Docker ----------------------------------------------------------------
if command -v docker >/dev/null 2>&1; then
  echo "[1/3] Docker ya está instalado."
else
  echo "[1/3] Instalando Docker (puede tardar un par de minutos)..."
  curl -fsSL https://get.docker.com | sh
fi

# 2) Código ----------------------------------------------------------------
if [ -f "$DIR/docker-compose.yml" ]; then
  echo "[2/3] Ya existe la carpeta '$DIR'."
  if [ -d "$DIR/.git" ]; then
    ( cd "$DIR" && git pull --ff-only ) || echo "     (no se pudo actualizar; sigo con lo que hay)"
  fi
else
  echo "[2/3] Descargando Hylanlock..."
  if command -v git >/dev/null 2>&1; then
    git clone "$REPO" "$DIR"
  else
    curl -fsSL "$TARBALL" | tar xz
    mv hylanlock-main "$DIR"
  fi
fi

# 3) Construir y arrancar ---------------------------------------------------
echo "[3/3] Construyendo y arrancando (la primera vez tarda un poco)..."
cd "$DIR"
docker compose up -d --build

# Información final ----------------------------------------------------------
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -z "$IP" ] && IP="LA-IP-DE-ESTE-SERVIDOR"
PORT="${HYLANLOCK_PORT:-8000}"

echo ""
echo "======================================"
echo "  ¡Listo!"
echo "======================================"
echo "  Abre en el navegador:  http://$IP:$PORT"
echo "  El asistente te guía: crea tu administrador e instala la licencia"
echo "  (el archivo .txt que te hemos adjuntado en el correo)."
echo ""
echo "  Se reinicia solo al encender el servidor. Para pararlo:"
echo "     cd $DIR && docker compose down"
echo "======================================"
