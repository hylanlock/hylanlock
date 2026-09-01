# 💾 Backups y restauración — Hylanlock

Copias de seguridad automáticas de **todo**: base de datos (usuarios, departamentos,
auditoría), archivos de cada departamento y del buzón, y el secreto de sesión.

## Qué se guarda y cómo

- La **BD** se copia con la *Online Backup API* de SQLite → snapshot **consistente**
  aunque la app esté funcionando (nunca un fichero a medias, aun con WAL).
- Los **archivos** (`entrada/`, `salida/`, `departamentos/…`) y `.session_secret` se
  empaquetan en un `.tar.gz` con fecha.
- Se guardan en `./backups/` con **rotación** (por defecto, los 14 más recientes).

## Hacer un backup ahora

```bash
./scripts/backup.sh
```

Genera `backups/hylanlock-AAAAMMDD-HHMMSS.tar.gz`.

## Automatizarlo (cron del host)

Backup diario a las 03:00 (ajusta la ruta del proyecto):

```bash
0 3 * * * cd /opt/hylanlock && ./scripts/backup.sh >> /var/log/hylanlock-backup.log 2>&1
```

Opciones (variables de entorno):

| Variable | Por defecto | Qué hace |
|---|---|---|
| `HYLANLOCK_BACKUP_DIR`  | `./backups`       | Carpeta destino |
| `HYLANLOCK_BACKUP_KEEP` | `14`              | Cuántos backups conservar |
| `HYLANLOCK_VOLUME`      | `<carpeta>_hylanlock_data` | Nombre del volumen (Compose le pone el prefijo del proyecto) |

## Restaurar

```bash
./scripts/restore.sh                              # lista los backups
./scripts/restore.sh hylanlock-20260821-030000.tar.gz
```

Pide confirmación (`SI`), **para el servicio**, restaura la BD y los archivos, y
vuelve a arrancar. 

> 🧪 **Prueba tu restore.** Un backup no probado no es un backup. Haz una prueba de
> restauración en un servidor de pruebas de vez en cuando: es la única forma de saber
> que podrás recuperarte de verdad.

## Llevar los backups fuera del servidor (recomendado)

Un backup en la misma máquina no protege ante un fallo del disco. Copia la carpeta
`backups/` a otro sitio (otro disco, NAS, o almacenamiento externo). Ejemplo con rsync:

```bash
0 4 * * * rsync -a /opt/hylanlock/backups/ usuario@nas:/backups/hylanlock/
```

## Notas

- Los `.tar.gz` contienen datos de la empresa: **guárdalos en un lugar seguro**.
- El backup **no interrumpe** el servicio (se hace en caliente).
- La restauración **sí** reinicia el servicio unos segundos.
