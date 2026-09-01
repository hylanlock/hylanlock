#!/usr/bin/env bash
# Instala el agente de Hylanlock para el usuario actual (Linux, systemd).
#
# Deja el agente corriendo cada 5 minutos y arrancando solo al iniciar sesión. No pide sudo:
# se instala en el ámbito del USUARIO, no del sistema, porque el agente sincroniza los archivos
# de esa persona con sus permisos, no los de la máquina.
#
# Uso:   ./instalar-agente.sh [--cada SEGUNDOS]
#        ./instalar-agente.sh --desinstalar

set -euo pipefail

NOMBRE="hylanlock-agente"
DESTINO_APP="$HOME/.local/share/hylanlock"
UNIDAD="$HOME/.config/systemd/user/$NOMBRE.service"
CADA=300

# ── Argumentos ──────────────────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cada)         CADA="${2:-300}"; shift 2 ;;
    --desinstalar)  DESINSTALAR=1; shift ;;
    -h|--help)      sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "Opción desconocida: $1" >&2; exit 1 ;;
  esac
done

# ── Desinstalación ──────────────────────────────────────────────────────────────────────────
if [[ -n "${DESINSTALAR:-}" ]]; then
  systemctl --user disable --now "$NOMBRE" 2>/dev/null || true
  rm -f "$UNIDAD"
  systemctl --user daemon-reload 2>/dev/null || true
  echo "🧹 Agente desinstalado."
  echo "   Tus archivos y tu configuración NO se han tocado: están en $DESTINO_APP"
  exit 0
fi

# ── Comprobaciones previas ──────────────────────────────────────────────────────────────────
AQUI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAQUETE=""
for candidato in "$AQUI/hylanlock-agente.pyz" "$AQUI/dist/hylanlock-agente.pyz" \
                 "$AQUI/hylanlock_agente.py"; do
  [[ -f "$candidato" ]] && { PAQUETE="$candidato"; break; }
done
if [[ -z "$PAQUETE" ]]; then
  echo "❌ No encuentro el agente junto a este script." >&2
  echo "   Copia aquí 'hylanlock-agente.pyz' y vuelve a intentarlo." >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "❌ Hace falta Python 3 y no lo encuentro." >&2
  exit 1
fi

if ! systemctl --user show-environment >/dev/null 2>&1; then
  echo "⚠️  No hay systemd de usuario disponible en esta sesión." >&2
  echo "   Puedes usar el agente a mano:  python3 $PAQUETE --cada $CADA" >&2
  exit 1
fi

# ── Instalación ─────────────────────────────────────────────────────────────────────────────
mkdir -p "$DESTINO_APP" "$(dirname "$UNIDAD")"
cp "$PAQUETE" "$DESTINO_APP/hylanlock-agente.pyz"
chmod 755 "$DESTINO_APP/hylanlock-agente.pyz"

CONFIG="$DESTINO_APP/hylanlock_agente.json"
if [[ ! -f "$CONFIG" ]]; then
  ( cd "$DESTINO_APP" && python3 hylanlock-agente.pyz --init >/dev/null )
  echo "📝 Configuración creada en:"
  echo "   $CONFIG"
  echo "   Ábrela y pon la dirección del servidor y TU token antes de seguir."
  echo "   El token se saca en la web: 👤 Mi perfil → 💻 Equipos sincronizados."
fi

cat > "$UNIDAD" <<UNIT
[Unit]
Description=Agente de sincronización de Hylanlock
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/env python3 $DESTINO_APP/hylanlock-agente.pyz --cada $CADA -c $CONFIG
Restart=on-failure
RestartSec=60

[Install]
WantedBy=default.target
UNIT

systemctl --user daemon-reload
systemctl --user enable "$NOMBRE" >/dev/null

echo "✅ Agente instalado en $DESTINO_APP"
echo
echo "   Cuando hayas puesto el token en la configuración, arráncalo:"
echo "     systemctl --user start $NOMBRE"
echo
echo "   Ver qué está haciendo:   journalctl --user -u $NOMBRE -f"
echo "   Pararlo:                 systemctl --user stop $NOMBRE"
echo "   Quitarlo:                ./instalar-agente.sh --desinstalar"
