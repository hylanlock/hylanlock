# -*- coding: utf-8 -*-
"""
Generador de codigo QR en Python puro (sin dependencias).
Modo byte, niveles de correccion, mascaras y placement segun el estandar QR.
Suficiente para codificar una URL corta como http://192.168.1.11:8000

Basado en el algoritmo estandar (implementacion de referencia estilo Nayuki).
"""

# ------------------------------------------------------- Galois Field GF(256)
_EXP = [0] * 256
_LOG = [0] * 256
_x = 1
for _i in range(256):
    _EXP[_i] = _x
    if _i < 255:
        _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D


def _gf_mul(a, b):
    if a == 0 or b == 0:
        return 0
    return _EXP[(_LOG[a] + _LOG[b]) % 255]


def _rs_divisor(degree):
    # Coeficientes del polinomio divisor (sin el termino lider), longitud = degree.
    result = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(degree):
            result[j] = _gf_mul(result[j], root)
            if j + 1 < degree:
                result[j] ^= result[j + 1]
        root = _gf_mul(root, 2)
    return result


def _rs_remainder(data, degree):
    divisor = _rs_divisor(degree)
    result = [0] * degree
    for b in data:
        factor = b ^ result[0]
        del result[0]
        result.append(0)
        for i in range(degree):
            result[i] ^= _gf_mul(divisor[i], factor)
    return result


# ------------------------------------------------------- Tablas nivel M (1-10)
# error-correction codewords por bloque
_ECC_PER_BLOCK_M = {1: 10, 2: 16, 3: 26, 4: 18, 5: 24,
                    6: 16, 7: 18, 8: 22, 9: 22, 10: 26}
# numero de bloques
_NUM_BLOCKS_M = {1: 1, 2: 1, 3: 1, 4: 2, 5: 2,
                 6: 4, 7: 4, 8: 4, 9: 5, 10: 5}
_ECL_FORMAT_BITS = 0  # nivel M


def _num_raw_data_modules(ver):
    result = (16 * ver + 128) * ver + 64
    if ver >= 2:
        numalign = ver // 7 + 2
        result -= (25 * numalign - 10) * numalign - 55
        if ver >= 7:
            result -= 36
    return result


def _alignment_positions(ver, size):
    if ver == 1:
        return []
    numalign = ver // 7 + 2
    step = (ver * 4 + numalign * 2 + 1) // (2 * numalign - 2) * 2
    result = [6]
    pos = size - 7
    for _ in range(numalign - 1):
        result.insert(1, pos)
        pos -= step
    return result


def _cci_bits(ver):
    return 8 if ver <= 9 else 16


def _pick_version(data_len):
    for ver in range(1, 11):
        raw_cw = _num_raw_data_modules(ver) // 8
        data_cw = raw_cw - _ECC_PER_BLOCK_M[ver] * _NUM_BLOCKS_M[ver]
        need_bits = 4 + _cci_bits(ver) + 8 * data_len
        if need_bits <= data_cw * 8:
            return ver, data_cw
    raise ValueError("Datos demasiado largos para QR v1-10")


def _encode_data(data_bytes, ver, data_cw):
    bits = []

    def put(val, n):
        for i in range(n - 1, -1, -1):
            bits.append((val >> i) & 1)

    put(0b0100, 4)                      # modo byte
    put(len(data_bytes), _cci_bits(ver))
    for b in data_bytes:
        put(b, 8)

    cap = data_cw * 8
    put(0, min(4, cap - len(bits)))     # terminador
    while len(bits) % 8:                 # relleno a byte
        bits.append(0)
    pad = [0xEC, 0x11]
    k = 0
    while len(bits) < cap:               # bytes de relleno
        put(pad[k % 2], 8)
        k += 1

    codewords = []
    for i in range(0, len(bits), 8):
        v = 0
        for b in bits[i:i + 8]:
            v = (v << 1) | b
        codewords.append(v)
    return codewords


def _add_ecc_interleave(data_cw_list, ver):
    numblocks = _NUM_BLOCKS_M[ver]
    ecclen = _ECC_PER_BLOCK_M[ver]
    raw_cw = _num_raw_data_modules(ver) // 8
    numshort = numblocks - raw_cw % numblocks
    shortlen = raw_cw // numblocks

    blocks = []
    k = 0
    for i in range(numblocks):
        datlen = (shortlen - ecclen) + (0 if i < numshort else 1)
        dat = data_cw_list[k:k + datlen]
        k += datlen
        ecc = _rs_remainder(dat, ecclen)
        blocks.append((dat, ecc))

    result = []
    maxdat = max(len(d) for d, _ in blocks)
    for i in range(maxdat):
        for d, _ in blocks:
            if i < len(d):
                result.append(d[i])
    for i in range(ecclen):
        for _, e in blocks:
            result.append(e[i])
    return result


# ------------------------------------------------------- Construccion matriz
def _new_matrix(size):
    return [[0] * size for _ in range(size)], [[False] * size for _ in range(size)]


def _draw_finder(m, f, size, r, c):
    for dr in range(-1, 8):
        for dc in range(-1, 8):
            rr, cc = r + dr, c + dc
            if 0 <= rr < size and 0 <= cc < size:
                dist = max(abs(dr - 3), abs(dc - 3))
                m[rr][cc] = 1 if (dist != 2 and dist != 4) else 0
                f[rr][cc] = True


def _draw_alignment(m, f, r, c):
    for dr in range(-2, 3):
        for dc in range(-2, 3):
            dist = max(abs(dr), abs(dc))
            m[r + dr][c + dc] = 1 if dist != 1 else 0
            f[r + dr][c + dc] = True


def _reserve_format(f, size):
    for i in range(9):
        f[8][i] = True
        f[i][8] = True
    for i in range(8):
        f[8][size - 1 - i] = True
        f[size - 1 - i][8] = True


_MASKS = [
    lambda r, c: (r + c) % 2 == 0,
    lambda r, c: r % 2 == 0,
    lambda r, c: c % 3 == 0,
    lambda r, c: (r + c) % 3 == 0,
    lambda r, c: (r // 2 + c // 3) % 2 == 0,
    lambda r, c: (r * c) % 2 + (r * c) % 3 == 0,
    lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
    lambda r, c: ((r + c) % 2 + (r * c) % 3) % 2 == 0,
]


def _place_data(m, f, size, allbits):
    idx = 0
    col = size - 1
    while col > 0:
        if col == 6:
            col = 5
        for i in range(size):
            for j in range(2):
                cc = col - j
                upward = ((col + 1) & 2) == 0
                rr = (size - 1 - i) if upward else i
                if not f[rr][cc]:
                    m[rr][cc] = allbits[idx] if idx < len(allbits) else 0
                    idx += 1
        col -= 2


def _apply_mask(m, f, size, mask):
    fn = _MASKS[mask]
    for r in range(size):
        for c in range(size):
            if not f[r][c] and fn(r, c):
                m[r][c] ^= 1


def _format_bits(mask):
    data = (_ECL_FORMAT_BITS << 3) | mask
    rem = data
    for _ in range(10):
        rem = (rem << 1) ^ ((rem >> 9) * 0x537)
    return ((data << 10) | rem) ^ 0x5412


def _draw_format(m, size, mask):
    bits = _format_bits(mask)

    def bit(i):
        return (bits >> i) & 1

    for i in range(6):
        m[i][8] = bit(i)
    m[7][8] = bit(6)
    m[8][8] = bit(7)
    m[8][7] = bit(8)
    for i in range(9, 15):
        m[8][14 - i] = bit(i)
    for i in range(8):
        m[8][size - 1 - i] = bit(i)
    for i in range(8, 15):
        m[size - 15 + i][8] = bit(i)
    m[size - 8][8] = 1  # modulo oscuro fijo


def _penalty(m, size):
    score = 0
    # Regla 1: corridas de >=5 iguales (filas y columnas)
    for line in (m, list(zip(*m))):
        for row in line:
            run = 1
            for i in range(1, size):
                if row[i] == row[i - 1]:
                    run += 1
                else:
                    if run >= 5:
                        score += 3 + (run - 5)
                    run = 1
            if run >= 5:
                score += 3 + (run - 5)
    # Regla 2: bloques 2x2
    for r in range(size - 1):
        for c in range(size - 1):
            v = m[r][c]
            if v == m[r][c + 1] == m[r + 1][c] == m[r + 1][c + 1]:
                score += 3
    # Regla 3: patron 1011101 con 4 blancos
    patt_a = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0]
    patt_b = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1]
    cols = list(zip(*m))
    for line in (m, cols):
        for row in line:
            row = list(row)
            for i in range(size - 10):
                seg = row[i:i + 11]
                if seg == patt_a or seg == patt_b:
                    score += 40
    # Regla 4: balance oscuro/claro
    dark = sum(sum(r) for r in m)
    total = size * size
    ratio = dark * 100 // total
    score += (abs(ratio - 50) // 5) * 10
    return score


def encode(text):
    """Devuelve la matriz QR (lista de listas de 0/1) para el texto dado."""
    data_bytes = text.encode("utf-8")
    ver, data_cw = _pick_version(len(data_bytes))
    size = ver * 4 + 17

    codewords = _encode_data(data_bytes, ver, data_cw)
    allcw = _add_ecc_interleave(codewords, ver)
    allbits = []
    for cw in allcw:
        for i in range(7, -1, -1):
            allbits.append((cw >> i) & 1)

    m, f = _new_matrix(size)
    _draw_finder(m, f, size, 0, 0)
    _draw_finder(m, f, size, 0, size - 7)
    _draw_finder(m, f, size, size - 7, 0)

    # timing
    for i in range(size):
        val = 1 if i % 2 == 0 else 0
        if not f[6][i]:
            m[6][i] = val
            f[6][i] = True
        if not f[i][6]:
            m[i][6] = val
            f[i][6] = True

    # alignment
    aligns = _alignment_positions(ver, size)
    last = size - 7
    for r in aligns:
        for c in aligns:
            if (r == 6 and c == 6) or (r == 6 and c == last) or (r == last and c == 6):
                continue
            _draw_alignment(m, f, r, c)

    m[size - 8][8] = 1
    f[size - 8][8] = True
    _reserve_format(f, size)

    _place_data(m, f, size, allbits)

    # elegir mejor mascara
    best_mask, best_score = 0, None
    best_matrix = None
    for mask in range(8):
        test = [row[:] for row in m]
        _apply_mask(test, f, size, mask)
        _draw_format(test, size, mask)
        sc = _penalty(test, size)
        if best_score is None or sc < best_score:
            best_score, best_mask, best_matrix = sc, mask, test

    return best_matrix


# ------------------------------------------------------- Render
def to_ansi(matrix, quiet=2):
    """QR para terminal usando medios bloques y colores forzados (blanco/negro)."""
    size = len(matrix)
    W = "\033[48;2;255;255;255m"   # fondo blanco
    K = "\033[48;2;0;0;0m"         # fondo negro
    R = "\033[0m"
    grid = [[0] * (size + 2 * quiet) for _ in range(size + 2 * quiet)]
    for r in range(size):
        for c in range(size):
            grid[r + quiet][c + quiet] = matrix[r][c]
    n = len(grid)
    lines = []
    for r in range(0, n, 2):
        line = []
        for c in range(n):
            top = grid[r][c]
            bot = grid[r + 1][c] if r + 1 < n else 0
            # oscuro=1 -> negro ; claro=0 -> blanco. Char medio-arriba.
            fg = "38;2;0;0;0" if top else "38;2;255;255;255"
            bg = "48;2;0;0;0" if bot else "48;2;255;255;255"
            line.append(f"\033[{fg};{bg}m▀")
        line.append(R)
        lines.append("".join(line))
    return "\n".join(lines)


def to_svg(matrix, quiet=4, module=8):
    """QR como SVG (negro sobre blanco), escalable y nitido para escanear."""
    size = len(matrix)
    dim = (size + 2 * quiet) * module
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{dim}" height="{dim}" '
        f'viewBox="0 0 {dim} {dim}" shape-rendering="crispEdges">',
        f'<rect width="{dim}" height="{dim}" fill="#ffffff"/>',
        '<path fill="#000000" d="',
    ]
    for r in range(size):
        for c in range(size):
            if matrix[r][c]:
                x = (c + quiet) * module
                y = (r + quiet) * module
                parts.append(f"M{x} {y}h{module}v{module}h-{module}z")
    parts.append('"/></svg>')
    return "".join(parts)


if __name__ == "__main__":
    import sys
    txt = sys.argv[1] if len(sys.argv) > 1 else "http://192.168.1.11:8000"
    print(to_ansi(encode(txt)))
