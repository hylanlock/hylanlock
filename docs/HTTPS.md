# 🔒 HTTPS para Hylanlock

Por defecto, Hylanlock habla **HTTP** (sin cifrar). Para una empresa, el tráfico debe ir **cifrado
(HTTPS)**: contraseñas, archivos y cookies de sesión no deben viajar en claro por la red local.

Este perfil pone **Caddy** (un servidor web ligero) **delante** de Hylanlock: Caddy cifra el tráfico y
le pasa las peticiones. Hylanlock queda atado a `127.0.0.1`, así **nadie puede saltarse el cifrado**
hablándole directamente.

## ⚠️ Por qué no es el "HTTPS automático" de siempre

El HTTPS automático que conocerás (Let's Encrypt) necesita un **dominio público** y validación **desde
internet**. Hylanlock vive en una **red local aislada**, sin salida — así que Let's Encrypt **no aplica**.
Hay tres formas de tener HTTPS aquí:

| Opción | Qué da | A tener en cuenta |
|---|---|---|
| **CA interna** (por defecto, `tls internal`) | Cifra sin configurar nada | El navegador avisa hasta instalar la CA de Caddy (o aceptar la excepción) |
| **Certificado propio** de la empresa | Sin avisos en vuestros equipos | Necesitáis el certificado (típico si tenéis dominio Windows/CA propia) |
| **Let's Encrypt por DNS** | Certificado reconocido | Avanzado: dominio + proveedor DNS soportado |

## ⚠️ Antes de empezar: los puertos 80 y 443 deben estar LIBRES

Caddy los ocupa (el 443 para HTTPS y el 80 para redirigir a HTTPS). Si en ese servidor ya hay algo
escuchando ahí — otro servidor web, un panel de administración, un túnel tipo Tailscale/Cloudflare —
**Caddy no arrancará** y se quedará reiniciándose una y otra vez. El síntoma es mudo: `docker
compose ps` dice `Restarting` y no hay ningún error en la pantalla. Compruébalo antes:

```bash
ss -tlnp | grep -E ':(80|443)\s'      # si no devuelve nada, están libres
docker logs hylanlock-caddy            # si ya falló: "bind: address already in use"
```

Si están ocupados, o liberas el puerto, o pones a Caddy en otro (`hylanlock.empresa.local:8443 {`
en el `Caddyfile`) y los usuarios entran por `https://hylanlock.empresa.local:8443`.

## 🚀 Cómo activarlo (opción por defecto, CA interna)

1. **Edita el `Caddyfile`**: cambia `hylanlock.empresa.local` por el nombre con el que accederéis.
2. Ese nombre **tiene que resolver a la IP del servidor**. Dos vías:
   - **DNS interno** (recomendado): una entrada en vuestro servidor DNS → IP del servidor.
   - **Archivo hosts** en cada equipo (para probar): añade `LA-IP-DE-TU-SERVIDOR  hylanlock.empresa.local`.
3. Levanta con el perfil HTTPS:
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.https.yml up -d --build
   ```
4. Entra en `https://hylanlock.empresa.local`. La primera vez el navegador **avisará** (certificado de
   CA interna). Para quitar el aviso, instala la CA de Caddy (paso siguiente) o acepta la excepción.

### Quitar el aviso del navegador (instalar la CA de Caddy)
La CA interna de Caddy vive en el volumen `caddy_data`. Extrae el certificado raíz e instálalo como
"entidad de certificación de confianza" en los equipos:
```bash
docker compose -f docker-compose.yml -f docker-compose.https.yml exec caddy \
  cat /data/caddy/pki/authorities/local/root.crt > hylanlock-ca.crt
```
Reparte `hylanlock-ca.crt` e instálalo en cada equipo (Windows: doble clic → *Instalar certificado* →
*Entidades de certificación raíz de confianza*). En un dominio Windows se puede repartir por GPO.

## 🏢 Cómo usar un certificado propio (sin avisos)

Si tenéis vuestro propio certificado (`cert.pem` + `key.pem`):
1. Colócalos junto al `Caddyfile`.
2. En el `Caddyfile`, comenta `tls internal` y descomenta:
   ```
   tls /etc/caddy/cert.pem /etc/caddy/key.pem
   ```
   (móntalos añadiendo `- ./cert.pem:/etc/caddy/cert.pem:ro` y la clave en el servicio `caddy`).
3. Vuelve a levantar con el perfil HTTPS.

## 🔐 El candado LAN sigue funcionando

Con Caddy delante, Hylanlock ya no ve la IP del cliente directamente, sino la de Caddy. El perfil lo
resuelve solo: pone `HYLANLOCK_TRUSTED_PROXIES=127.0.0.1/32`, así Hylanlock **confía en Caddy** y lee la
IP real del cliente de la cabecera `X-Forwarded-For` que Caddy añade. El aislamiento por red local se
mantiene intacto. (Un cliente cualquiera **no** puede falsear esa cabecera: solo se lee si la conexión
viene del proxy de confianza.)

## Volver a HTTP

Simplemente levanta sin el perfil: `docker compose up -d`. (Quita antes el contenedor de Caddy con
`docker rm -f hylanlock-caddy` si sigue vivo.)
