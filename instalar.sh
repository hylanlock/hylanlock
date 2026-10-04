#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
# Instalador de Hylanlock (Linux) — un solo comando.
#
#   curl -fsSL https://raw.githubusercontent.com/hylanlock/hylanlock/main/instalar.sh | sudo sh
#
# Qué hace:
#   1) Instala Docker si no está (y se asegura de que el servicio esté arrancado).
#   2) Descarga Hylanlock (git si está disponible; si no, un .tar.gz).
#   3) Lo construye y lo arranca, y comprueba que responde.
#   4) Te dice la dirección para abrir en el navegador.
#
# No pide más datos: usa los valores por defecto (el .env es opcional). Para personalizar
# después, edita el .env dentro de la carpeta 'hylanlock' y vuelve a  docker compose up -d --build.
# ─────────────────────────────────────────────────────────────────────────────
set -eu

DIR="${HYLANLOCK_DIR:-hylanlock}"
REPO="https://github.com/hylanlock/hylanlock.git"
TARBALL="https://github.com/hylanlock/hylanlock/archive/refs/heads/main.tar.gz"
PORT="${HYLANLOCK_PORT:-8000}"

# Si algo falla, NO salimos en silencio: explicamos las causas más comunes. Antes, un fallo
# (p. ej. un proxy corporativo bloqueando las descargas) dejaba al usuario sin ninguna pista.
on_error() {
  code=$?
  echo "" >&2
  echo "======================================" >&2
  echo "  La instalacion se detuvo (error $code)." >&2
  echo "======================================" >&2
  echo "  Causas mas comunes:" >&2
  echo "   - Sin internet, o un PROXY de empresa bloquea las descargas. Docker necesita" >&2
  echo "     bajar su imagen base; si hay proxy, hay que configurarlo TAMBIEN en Docker:" >&2
  echo "     /etc/systemd/system/docker.service.d/http-proxy.conf (y 'systemctl restart docker')." >&2
  echo "   - El servicio de Docker no esta arrancado:  sudo systemctl start docker" >&2
  echo "   - Faltan permisos: ejecuta el comando con sudo." >&2
  echo "  Revisa el error de mas arriba y reintenta. Soporte: hylanlock@gmail.com" >&2
  exit "$code"
}
trap on_error EXIT

echo "======================================"
echo "  Instalacion de Hylanlock"
echo "======================================"

# 1) Docker ----------------------------------------------------------------
if command -v docker >/dev/null 2>&1; then
  echo "[1/3] Docker ya esta instalado."
else
  echo "[1/3] Instalando Docker (puede tardar un par de minutos)..."
  curl -fsSL https://get.docker.com | sh
fi

# Asegurar que el demonio de Docker responde (si no, intentar arrancarlo).
if ! docker info >/dev/null 2>&1; then
  echo "      Arrancando el servicio de Docker..."
  (systemctl start docker 2>/dev/null || service docker start 2>/dev/null) || true
  sleep 3
fi
if ! docker info >/dev/null 2>&1; then
  echo "No se puede hablar con el demonio de Docker (arrancalo con: sudo systemctl start docker)." >&2
  exit 1
fi

# Detectar Docker Compose: v2 ('docker compose') o v1 ('docker-compose').
if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"
else
  echo "No se encontro Docker Compose (deberia venir con Docker)." >&2
  exit 1
fi

# 2) Codigo ----------------------------------------------------------------
if [ -f "$DIR/docker-compose.yml" ]; then
  echo "[2/3] Ya existe la carpeta '$DIR'."
  if [ -d "$DIR/.git" ]; then
    ( cd "$DIR" && git pull --ff-only ) || echo "      (no se pudo actualizar; sigo con lo que hay)"
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
$COMPOSE up -d --build

# Comprobar que el servicio responde de verdad.
echo "      Comprobando que arranca..."
ok=""
i=0
while [ "$i" -lt 20 ]; do
  if curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then ok="si"; break; fi
  i=$((i + 1)); sleep 1
done

# IP real de este servidor (la de salida; evita la IP del puente interno de Docker 172.17.x).
IP="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(j=1;j<=NF;j++) if($j=="src"){print $(j+1); exit}}')"
[ -z "$IP" ] && IP="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -v '^172\.17\.' | grep . | head -1)"
[ -z "$IP" ] && IP="LA-IP-DE-ESTE-SERVIDOR"

trap - EXIT   # a partir de aqui todo fue bien: desactivar el mensaje de error.

echo ""
echo "======================================"
if [ "$ok" = "si" ]; then
  echo "  Listo. El servicio ya responde."
else
  echo "  Instalado. (Aun terminando de arrancar; dale un minuto.)"
fi
echo "======================================"
echo "  Abre en el navegador:  http://$IP:$PORT"
echo "  El asistente te guia: crea tu administrador e instala la licencia"
echo "  (el archivo .txt que te hemos adjuntado en el correo)."
echo ""
echo "  Se reinicia solo al encender el servidor. Para pararlo:"
echo "     cd $DIR && $COMPOSE down"
echo "======================================"
