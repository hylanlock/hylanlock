#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
# Hylanlock — backup automatizado.
# Hace un snapshot CONSISTENTE de la BD (SQLite Online Backup API) + empaqueta
# los archivos del volumen en un .tar.gz, con rotación. Ejecutar desde la carpeta
# del proyecto (donde está docker-compose.yml). Pensado para cron del host.
#
#   ./scripts/backup.sh
#
# Variables opcionales:
#   HYLANLOCK_BACKUP_DIR   carpeta destino (por defecto ./backups)
#   HYLANLOCK_BACKUP_KEEP  cuántos backups conservar (por defecto 14)
#   HYLANLOCK_VOLUME       nombre del volumen (por defecto hylanlock_data)
# ─────────────────────────────────────────────────────────────────────────────
set -eu

BACKUP_DIR="${HYLANLOCK_BACKUP_DIR:-./backups}"
KEEP="${HYLANLOCK_BACKUP_KEEP:-14}"
# Compose nombra el volumen como "<carpeta-del-proyecto>_hylanlock_data".
VOLUME="${HYLANLOCK_VOLUME:-$(basename "$(pwd)")_hylanlock_data}"
STAMP="$(date +%Y%m%d-%H%M%S)"

mkdir -p "$BACKUP_DIR"
OUT_ABS="$(cd "$BACKUP_DIR" && pwd)"

echo "[1/3] Snapshot consistente de la BD (dentro del contenedor)…"
docker compose exec -T hylanlock python db.py backup /data/.backup.db

echo "[2/3] Empaquetando datos -> $BACKUP_DIR/hylanlock-$STAMP.tar.gz"
docker run --rm \
  -v "$VOLUME":/data:ro \
  -v "$OUT_ABS":/out \
  alpine tar czf "/out/hylanlock-$STAMP.tar.gz" -C /data \
    --exclude=.incompletos \
    --exclude=hylanlock.db \
    --exclude=hylanlock.db-wal \
    --exclude=hylanlock.db-shm \
    .

echo "[3/3] Rotación (conservar los $KEEP más recientes)…"
ls -1t "$OUT_ABS"/hylanlock-*.tar.gz 2>/dev/null | tail -n +"$((KEEP + 1))" | while read -r old; do
  rm -f "$old"
  echo "  borrado antiguo: $(basename "$old")"
done

echo "OK. Backups actuales:"
ls -1t "$OUT_ABS"/hylanlock-*.tar.gz 2>/dev/null | head -n "$KEEP" | while read -r f; do
  echo "  $(basename "$f")  ($(du -h "$f" | cut -f1))"
done
