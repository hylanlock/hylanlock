# 🚀 Instalar Hylanlock

Guía para instalar Hylanlock en un servidor **Linux** de tu empresa.

**Requisitos:** un servidor Linux en tu red local, con **Docker** y el plugin **Compose**
(`docker compose`). El servidor debe estar en la misma red que los equipos que usarán la aplicación.

## 1. Configura tus valores

```bash
cp .env.example .env
nano .env
```

Lo mínimo que debes ajustar:
- `HYLANLOCK_LAN_CIDR` → la subred de tu oficina (ej. `192.168.1.0/24`). Es lo que define "tu red local".
- (Opcional) `HYLANLOCK_PORT` si el 8000 está ocupado.

> No hace falta que definas el administrador aquí: en el primer arranque, un **asistente** en el
> navegador te guía para crearlo (paso 3). Si prefieres crearlo sin asistente, define
> `HYLANLOCK_ADMIN_USER` y `HYLANLOCK_ADMIN_PASSWORD` en el `.env`.

## 2. Arranca

```bash
docker compose up -d --build
docker compose ps        # STATUS debe poner "healthy"
```

## 3. Primer arranque: crea el administrador e instala tu licencia

Abre en el navegador `http://IP-DEL-SERVIDOR:8000` (o el puerto que pusieras).

1. **Asistente de instalación:** la primera vez aparece un asistente. Crea tu **cuenta de
   administrador** (usuario + contraseña).
2. **Instala tu licencia:** pega en el asistente (o después, en **Administración → 🪪 Licencia**) la
   **licencia** que te hemos facilitado. Sin una licencia válida, la aplicación queda bloqueada (pero
   **tus datos nunca se tocan**: al poner una licencia válida, todo se reactiva).
   - Alternativa: coloca el archivo `license.key` en la carpeta de datos del servidor.

## 4. Empieza a usarlo

Desde **Administración** creas **departamentos** y **usuarios**. Cada usuario recibe un enlace de un
solo uso para poner su propia contraseña. Consulta la ayuda en la propia interfaz.

## ⭐ Extras (opcionales pero recomendados)

- **🔒 HTTPS (cifrado):** por defecto la app va por HTTP. Para cifrar el tráfico, sigue **`HTTPS.md`**
  (perfil con Caddy).
- **🔄 Agente de sincronización:** para que los archivos lleguen solos a los PCs de los usuarios,
  reparte la carpeta **`agente/`** (ver `agente/README.md`).
- **💾 Copias de seguridad:** ver **`BACKUPS.md`** (`scripts/backup.sh` / `scripts/restore.sh`).

## 📦 Dónde viven los datos

Todo (base de datos, sesiones, licencia y archivos de cada departamento) se guarda en el volumen
**`hylanlock_data`** montado en `/data`. Al actualizar o reiniciar **no se pierde nada**.

```
/data/
├── hylanlock.db            # usuarios, departamentos, permisos, auditoría
├── .session_secret         # secreto de sesiones
├── license.key             # tu licencia
└── departamentos/<slug>/   # una carpeta por departamento (y sus subcarpetas)
```

> Para ver los archivos directamente en el host (backups a mano), usa el *bind-mount* comentado en
> `docker-compose.yml` (`./data:/data`) y da permisos: `sudo chown -R 10001:10001 ./data`.

## 🌐 Sobre la red (importante)

Hylanlock usa `network_mode: host` para ver la **IP real** de cada equipo y así saber quién está en la
**red local**. El aislamiento por departamento es *solo LAN* y depende de esto — no lo cambies salvo
que sepas lo que haces. (Detrás del perfil HTTPS de Caddy, la IP real se conserva; ver `HTTPS.md`.)

## 🔁 Parar / actualizar

```bash
docker compose down                 # parar (los datos se conservan)
docker compose up -d --build        # actualizar a una nueva versión
```

## 🔒 Seguridad

- El login se exige **siempre**, también desde el propio servidor: no hay forma de saltárselo.
- El contenedor corre como usuario **sin privilegios** (UID 10001), no como root.
- Las contraseñas se guardan cifradas de forma irreversible: **nadie**, ni el administrador, puede verlas.
- Para producción, activa **HTTPS** (`HTTPS.md`) antes de usarlo con datos reales.
