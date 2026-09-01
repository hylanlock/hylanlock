"""
Autenticación contra Active Directory / LDAP — OPCIONAL.

Solo se usa si HYLANLOCK_LDAP_ENABLED=1. Requiere la librería **ldap3** (Python puro), que se
instala SOLO cuando la empresa activa AD: el núcleo del producto no depende de ella. El import es
PEREZOSO — si ldap3 no está y AD está OFF, no pasa nada.

La contraseña del usuario NUNCA se guarda ni se cachea: solo se usa para el bind en ese instante.
El login del producto la trata así:
    resultado = ldap_login(cfg, usuario, contraseña)
      · dict  -> autenticado; contiene scope/boss/memberships derivados de sus grupos de AD.
      · None  -> credenciales inválidas (o el usuario no está en el directorio).
      · False -> el directorio no está disponible (ldap3 no instalado, AD caído, TLS...) ->
                 el login cae con gracia a las cuentas LOCALES (nunca te deja fuera).
"""

import ssl


def ldap3_available():
    try:
        import ldap3  # noqa: F401
        return True
    except Exception:
        return False


LDAP_AVAILABLE = ldap3_available()


def _parse_group_map(raw):
    """'GrupoAD:slug:rol, GrupoAD2:slug2:head' -> {nombre_grupo_lower: (slug, 'member'|'head')}."""
    out = {}
    for part in (raw or "").split(","):
        bits = [b.strip() for b in part.split(":")]
        if len(bits) >= 2 and bits[0] and bits[1]:
            rol = bits[2] if len(bits) >= 3 else "member"
            out[bits[0].lower()] = (bits[1], "head" if rol == "head" else "member")
    return out


def _group_cns(values):
    """De una lista de DNs de grupo ('CN=Ventas,OU=..,DC=..') saca el CN en minúsculas: {'ventas'}."""
    names = set()
    for g in values or []:
        first = str(g).split(",", 1)[0]
        cn = first.split("=", 1)[1] if "=" in first else first
        cn = cn.strip().lower()
        if cn:
            names.add(cn)
    return names


# Límites de la expansión de grupos anidados. Un directorio mal montado puede tener ciclos
# (A miembro de B, B miembro de A) o jerarquías absurdamente profundas: sin tope, resolver un
# login podría dar vueltas para siempre. Se corta y se sigue con lo que se haya encontrado.
MAX_PROFUNDIDAD = 10
MAX_GRUPOS = 200

# OID de Active Directory (LDAP_MATCHING_RULE_IN_CHAIN): resuelve TODA la cadena de grupos
# anidados en una sola consulta. Solo lo entiende AD; OpenLDAP lo ignora o da error, y por eso
# hay un camino alternativo a pelo.
AD_EN_CADENA = "1.2.840.113556.1.4.1941"


def _cadena_ad(conn, base_dn, user_dn, escape):
    """Camino RÁPIDO (Active Directory): una consulta devuelve todos los grupos del usuario,
    directos y heredados. Devuelve la lista de DNs, o None si el directorio no soporta la regla."""
    try:
        flt = "(member:%s:=%s)" % (AD_EN_CADENA, escape(user_dn))
        conn.search(base_dn, flt, attributes=["cn"])
        return [e.entry_dn for e in conn.entries] or None
    except Exception:
        return None                                   # no es AD (o no la admite) -> camino a pelo


def _cadena_a_pelo(conn, dns_directos):
    """Camino PORTABLE (OpenLDAP y cualquier otro): partiendo de los grupos directos del usuario,
    va preguntando por el 'memberOf' de cada grupo para subir de nivel en nivel.

    Un grupo puede pertenecer a otro grupo, y esa pertenencia también cuenta: si 'VentasNorte' está
    dentro de 'Ventas', quien esté en VentasNorte trabaja en Ventas. Lleva un conjunto de visitados
    para no repetir ni quedarse atrapado en un ciclo."""
    vistos = set(dns_directos)
    frontera = list(dns_directos)
    for _ in range(MAX_PROFUNDIDAD):
        if not frontera or len(vistos) >= MAX_GRUPOS:
            break
        siguiente = []
        for dn in frontera:
            try:
                conn.search(dn, "(objectClass=*)", search_scope="BASE", attributes=["memberOf"])
            except Exception:
                continue                              # ese grupo no se puede leer: se ignora
            if not conn.entries:
                continue
            e = conn.entries[0]
            padres = e.memberOf.values if "memberOf" in e else []
            for p in padres:
                p = str(p)
                if p not in vistos and len(vistos) < MAX_GRUPOS:
                    vistos.add(p)
                    siguiente.append(p)
        frontera = siguiente
    return vistos


def _todos_los_grupos(conn, base_dn, user_dn, dns_directos, escape):
    """Todos los grupos que le tocan al usuario: los suyos y los que hereda por anidamiento."""
    encadena = _cadena_ad(conn, base_dn, user_dn, escape)
    if encadena:
        return set(dns_directos) | set(encadena)
    return _cadena_a_pelo(conn, dns_directos)


def ldap_login(cfg, username, password):
    """Autentica (username, password) contra el directorio. Ver el docstring del módulo para el
    contrato de retorno (dict / None / False)."""
    if not cfg.get("enabled") or not username or not password:
        return None
    if not LDAP_AVAILABLE:
        return False                                  # AD activado pero falta ldap3 -> caer a local

    import ldap3
    from ldap3.core.exceptions import LDAPException
    from ldap3.utils.conv import escape_filter_chars

    uri = cfg.get("uri", "")
    use_ssl = uri.lower().startswith("ldaps")
    try:
        tls = None
        if use_ssl:
            ca = cfg.get("tls_cacert") or None
            # Con CA -> validar el certificado del DC (recomendado). Sin CA -> no validar (avisar en docs).
            tls = ldap3.Tls(validate=ssl.CERT_REQUIRED if ca else ssl.CERT_NONE,
                            ca_certs_file=ca)
        server = ldap3.Server(uri, use_ssl=use_ssl, tls=tls, connect_timeout=8, get_info=None)

        # 1) Bind con la cuenta de SERVICIO (solo lectura) para localizar al usuario y sus grupos.
        svc = ldap3.Connection(server, user=cfg.get("bind_dn") or None,
                               password=cfg.get("bind_pw") or None,
                               auto_bind=True, receive_timeout=8)
        flt = cfg.get("user_filter", "(sAMAccountName=%s)").replace(
            "%s", escape_filter_chars(username))
        svc.search(cfg.get("base_dn", ""), flt, attributes=["memberOf"])
        if not svc.entries:
            svc.unbind()
            return None                               # el usuario no existe en el directorio
        entry = svc.entries[0]
        user_dn = entry.entry_dn
        member_of = [str(g) for g in (entry.memberOf.values if "memberOf" in entry else [])]
        # Grupos ANIDADOS: en una empresa real los grupos cuelgan unos de otros ('VentasNorte'
        # dentro de 'Ventas'). Quedarse solo con los directos deja fuera a gente que sí tiene
        # derecho, y eso se traduce en "no veo mi carpeta" el primer día.
        todos = _todos_los_grupos(svc, cfg.get("base_dn", ""), user_dn, member_of,
                                  escape_filter_chars)
        groups = _group_cns(todos)
        svc.unbind()

        # 2) Bind con las credenciales DEL USUARIO = la autenticación real.
        try:
            uc = ldap3.Connection(server, user=user_dn, password=password,
                                  auto_bind=True, receive_timeout=8)
            uc.unbind()
        except LDAPException:
            return None                               # contraseña incorrecta o cuenta deshabilitada

        # 3) Mapear grupos de AD -> scope / boss / membresías de departamento.
        gmap = _parse_group_map(cfg.get("group_map", ""))
        admin_g = (cfg.get("admin_group") or "").strip().lower()
        boss_g = (cfg.get("boss_group") or "").strip().lower()
        scope = "admin" if admin_g and admin_g in groups else "member"
        boss = 1 if boss_g and boss_g in groups else 0
        memberships = [gmap[g] for g in groups if g in gmap]
        return {"username": username, "scope": scope, "boss": boss, "memberships": memberships}

    except LDAPException:
        return False                                  # directorio caído / TLS / red -> caer a local
    except Exception:
        return False
