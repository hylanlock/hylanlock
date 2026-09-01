#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
# Hylanlock — restaurar desde un backup.
# ⚠️ DETIENE el servicio y reemplaza la BD por la del backup. Los archivos del
# backup se extraen sobre el volumen. Ejecutar desde la carpeta del proyecto.
#
#   ./scripts/restore.sh                       (lista los backups disponibles)
#   ./scripts/restore.sh hylanlock-AAAAMMDD-HHMMSS.tar.gz
#   ./scripts/restore.sh --yes <archivo.tar.gz>   (desatendido: sin preguntar)
#
# Por defecto pide teclear SI, que es lo correcto para una acción que machaca datos. Para una
# PRUEBA DE RECUPERACIÓN programada (cron), usa --yes / -y o exporta HYLANLOCK_ASSUME_YES=1.
# ─────────────────────────────────────────────────────────────────────────────
set -eu

BACKUP_DIR="${HYLANLOCK_BACKUP_DIR:-./backups}"
# Compose nombra el volumen como "<carpeta-del-proyecto>_hylanlock_data".
VOLUME="${HYLANLOCK_VOLUME:-$(basename "$(pwd)")_hylanlock_data}"

# Acepta el archivo y la bandera --yes/-y en cualquier orden.
ASSUME_YES="${HYLANLOCK_ASSUME_YES:-0}"
FILE=""
for arg in "$@"; do
  case "$arg" in
    -y|--yes) ASSUME_YES=1 ;;
    -*) echo "Opción desconocida: $arg" >&2; exit 2 ;;
    *) FILE="$arg" ;;
  esac
done

if [ -z "$FILE" ]; then
  echo "Uso: ./scripts/restore.sh [--yes] <archivo.tar.gz>"
  echo "Backups disponibles en $BACKUP_DIR:"
  ls -1t "$BACKUP_DIR"/hylanlock-*.tar.gz 2>/dev/null || echo "  (ninguno)"
  exit 1
fi

# Permite pasar solo el nombre (busca en BACKUP_DIR) o una ruta completa.
[ -f "$FILE" ] || FILE="$BACKUP_DIR/$FILE"
[ -f "$FILE" ] || { echo "No existe el archivo: $FILE"; exit 1; }

if [ "$ASSUME_YES" = "1" ]; then
  printf "⚠️  Restaurando SIN confirmación (--yes) desde '%s'.\n" "$FILE"
else
  printf "⚠️  Esto REEMPLAZA los datos actuales con '%s'.\n" "$FILE"
  printf "    Escribe SI (mayúsculas) para continuar: "
  read ans
  [ "$ans" = "SI" ] || { echo "Cancelado."; exit 1; }
fi

FNAME="$(basename "$FILE")"
INDIR="$(cd "$(dirname "$FILE")" && pwd)"

echo "[1/3] Parando el servicio…"
docker compose down

echo "[2/3] Restaurando datos en el volumen $VOLUME…"
docker run --rm \
  -v "$VOLUME":/data \
  -v "$INDIR":/in:ro \
  -e FNAME="$FNAME" \
  alpine sh -c '
    set -e
    cd /data
    rm -f hylanlock.db hylanlock.db-wal hylanlock.db-shm
    tar xzf "/in/$FNAME"
    if [ -f .backup.db ]; then mv -f .backup.db hylanlock.db; fi
    echo "  datos restaurados."
  '

echo "[3/3] Arrancando…"
docker compose up -d
echo "OK. Restaurado desde $FILE"
