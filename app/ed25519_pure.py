"""
Ed25519 en Python puro — SIN dependencias (solo hashlib de la stdlib).

Basado en la implementación de REFERENCIA de dominio público de Ed25519 (D. J. Bernstein
et al., RFC 8032). Es correcta pero LENTA: una verificación tarda ~1 s. Por eso en Hylanlock
solo se usa de forma puntual (al arrancar, al subir una licencia y en un refresco horario), y el
resultado se cachea; en cada petición solo se comparan fechas, que es barato.

El producto SOLO usa `verify()` con la clave pública embebida. `sign()`/`publickey()` los usa
nuestra herramienta interna de emisión de licencias (la clave privada nunca se distribuye).

API de alto nivel:
    verify(signature: bytes, message: bytes, public_key: bytes) -> bool
    sign(message: bytes, secret_key: bytes) -> bytes            # 64 bytes de firma
    publickey(secret_key: bytes) -> bytes                       # 32 bytes de clave pública
"""

import sys
import hashlib

# La recursión de scalarmult/expmod puede acercarse a ~256 niveles; damos margen.
sys.setrecursionlimit(10000)

b = 256
q = 2 ** 255 - 19
l = 2 ** 252 + 27742317777372353535851937790883648493


def _H(m):
    return hashlib.sha512(m).digest()


def _expmod(base, e, m):
    if e == 0:
        return 1
    t = _expmod(base, e // 2, m) ** 2 % m
    if e & 1:
        t = (t * base) % m
    return t


def _inv(x):
    return _expmod(x, q - 2, q)


d = -121665 * _inv(121666) % q
I = _expmod(2, (q - 1) // 4, q)


def _xrecover(y):
    xx = (y * y - 1) * _inv(d * y * y + 1)
    x = _expmod(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * I) % q
    if x % 2 != 0:
        x = q - x
    return x


_By = 4 * _inv(5) % q
_Bx = _xrecover(_By)
B = [_Bx % q, _By % q]


def _edwards(P, Q):
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + d * x1 * x2 * y1 * y2) % q
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - d * x1 * x2 * y1 * y2) % q
    return [x3 % q, y3 % q]


def _scalarmult(P, e):
    if e == 0:
        return [0, 1]
    Q = _scalarmult(P, e // 2)
    Q = _edwards(Q, Q)
    if e & 1:
        Q = _edwards(Q, P)
    return Q


def _encodeint(y):
    bits = [(y >> i) & 1 for i in range(b)]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(b // 8))


def _encodepoint(P):
    x, y = P
    bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(b // 8))


def _bit(h, i):
    return (h[i // 8] >> (i % 8)) & 1


def publickey(sk):
    """Deriva la clave pública (32 bytes) de una semilla secreta de 32 bytes."""
    h = _H(sk)
    a = 2 ** (b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, b - 2))
    A = _scalarmult(B, a)
    return _encodepoint(A)


def _Hint(m):
    h = _H(m)
    return sum(2 ** i * _bit(h, i) for i in range(2 * b))


def sign(m, sk, pk=None):
    """Firma el mensaje m (bytes) con la semilla secreta sk (32 bytes). Devuelve 64 bytes."""
    if pk is None:
        pk = publickey(sk)
    h = _H(sk)
    a = 2 ** (b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, b - 2))
    r = _Hint(bytes(h[i] for i in range(b // 8, b // 4)) + m)
    R = _scalarmult(B, r)
    S = (r + _Hint(_encodepoint(R) + pk + m) * a) % l
    return _encodepoint(R) + _encodeint(S)


def _isoncurve(P):
    x, y = P
    return (-x * x + y * y - 1 - d * x * x * y * y) % q == 0


def _decodeint(s):
    return sum(2 ** i * _bit(s, i) for i in range(0, b))


def _decodepoint(s):
    y = sum(2 ** i * _bit(s, i) for i in range(0, b - 1))
    x = _xrecover(y)
    if x & 1 != _bit(s, b - 1):
        x = q - x
    P = [x, y]
    if not _isoncurve(P):
        raise ValueError("punto fuera de la curva")
    return P


def _checkvalid(s, m, pk):
    if len(s) != b // 4:
        raise ValueError("longitud de firma incorrecta")
    if len(pk) != b // 8:
        raise ValueError("longitud de clave pública incorrecta")
    R = _decodepoint(s[0:b // 8])
    A = _decodepoint(pk)
    S = _decodeint(s[b // 8:b // 4])
    h = _Hint(_encodepoint(R) + pk + m)
    return _scalarmult(B, S) == _edwards(R, _scalarmult(A, h))


def verify(signature, message, public_key):
    """True si 'signature' (64 bytes) es una firma válida de 'message' bajo 'public_key' (32 bytes).
    Nunca lanza: cualquier fallo/corrupción -> False."""
    try:
        return _checkvalid(signature, message, public_key)
    except Exception:
        return False
