"""Minimal QR code encoder (byte mode, error correction level M), rendered as SVG.

Enough for subscription links (up to ~1.2 KB of text). Standard library only, so the panel
never has to load a script from a third-party CDN.
"""
import re

# (total codewords, ec codewords per block, blocks in group 1, data cw g1, blocks g2, data cw g2) for level M
_M = {
    1: (26, 10, 1, 16, 0, 0), 2: (44, 16, 1, 28, 0, 0), 3: (70, 26, 1, 44, 0, 0), 4: (100, 18, 2, 32, 0, 0),
    5: (134, 24, 2, 43, 0, 0), 6: (172, 16, 4, 27, 0, 0), 7: (196, 18, 4, 31, 0, 0), 8: (242, 22, 2, 38, 2, 39),
    9: (292, 22, 3, 36, 2, 37), 10: (346, 26, 4, 43, 1, 44), 11: (404, 30, 1, 50, 4, 51),
    12: (466, 22, 6, 36, 2, 37), 13: (532, 22, 8, 37, 1, 38), 14: (581, 24, 4, 40, 5, 41),
    15: (655, 24, 5, 41, 5, 42), 16: (733, 28, 7, 45, 3, 46), 17: (815, 28, 10, 46, 1, 47),
    18: (901, 26, 9, 43, 4, 44), 19: (991, 26, 3, 44, 11, 45), 20: (1085, 26, 3, 41, 13, 42),
    21: (1156, 26, 17, 42, 0, 0), 22: (1258, 28, 17, 46, 0, 0), 23: (1364, 28, 4, 47, 14, 48),
    24: (1474, 28, 6, 45, 14, 46), 25: (1588, 28, 8, 47, 13, 48),
}

_ALIGN = {
    1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42],
    9: [6, 26, 46], 10: [6, 28, 50], 11: [6, 30, 54], 12: [6, 32, 58], 13: [6, 34, 62], 14: [6, 26, 46, 66],
    15: [6, 26, 48, 70], 16: [6, 26, 50, 74], 17: [6, 30, 54, 78], 18: [6, 30, 56, 82], 19: [6, 30, 58, 86],
    20: [6, 34, 62, 90], 21: [6, 28, 50, 72, 94], 22: [6, 26, 50, 74, 98], 23: [6, 30, 54, 78, 102],
    24: [6, 28, 54, 80, 106], 25: [6, 32, 58, 84, 110],
}

# GF(256) with polynomial 0x11d
_EXP = [0] * 512
_LOG = [0] * 256
_v = 1
for _i in range(255):
    _EXP[_i] = _v
    _LOG[_v] = _i
    _v <<= 1
    if _v & 0x100:
        _v ^= 0x11d
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _mul(a, b):
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def _generator(n):
    g = [1]
    for i in range(n):
        g = [a ^ b for a, b in zip(g + [0], [0] + [_mul(c, _EXP[i]) for c in g])]
    return g


def _ec(data, n):
    gen = _generator(n)
    res = list(data) + [0] * n
    for i in range(len(data)):
        coef = res[i]
        if coef:
            for j in range(1, len(gen)):
                res[i + j] ^= _mul(gen[j], coef)
    return res[len(data):]


def _bits(value, length):
    return [(value >> (length - 1 - i)) & 1 for i in range(length)]


def _codewords(data, ver):
    total, ecn, b1, d1, b2, d2 = _M[ver]
    cap = b1 * d1 + b2 * d2
    bits = [0, 1, 0, 0] + _bits(len(data), 8 if ver < 10 else 16)
    for byte in data:
        bits += _bits(byte, 8)
    bits += [0] * min(4, cap * 8 - len(bits))
    bits += [0] * (-len(bits) % 8)
    cws = [int(''.join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = [0xEC, 0x11]
    while len(cws) < cap:
        cws.append(pad[(len(cws) - len(bits) // 8) % 2])
    blocks, pos = [], 0
    for count, size in ((b1, d1), (b2, d2)):
        for _ in range(count):
            blocks.append(cws[pos:pos + size])
            pos += size
    ecs = [_ec(b, ecn) for b in blocks]
    out = []
    for i in range(max(len(b) for b in blocks)):
        out += [b[i] for b in blocks if i < len(b)]
    for i in range(ecn):
        out += [e[i] for e in ecs]
    return out


def _format_bits(mask):
    data = (0b00 << 3) | mask          # level M = 00
    v = data << 10
    for i in range(14, 9, -1):
        if v & (1 << i):
            v ^= 0x537 << (i - 10)
    return ((data << 10) | v) ^ 0x5412


def _version_bits(ver):
    v = ver << 12
    for i in range(17, 11, -1):
        if v & (1 << i):
            v ^= 0x1F25 << (i - 12)
    return (ver << 12) | v


_MASKS = [
    lambda r, c: (r + c) % 2 == 0, lambda r, c: r % 2 == 0, lambda r, c: c % 3 == 0,
    lambda r, c: (r + c) % 3 == 0, lambda r, c: (r // 2 + c // 3) % 2 == 0,
    lambda r, c: (r * c) % 2 + (r * c) % 3 == 0, lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
    lambda r, c: ((r + c) % 2 + (r * c) % 3) % 2 == 0,
]


def _base(ver):
    n = ver * 4 + 17
    m = [[None] * n for _ in range(n)]

    def finder(r, c):
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                rr, cc = r + dr, c + dc
                if 0 <= rr < n and 0 <= cc < n:
                    inside = 0 <= dr <= 6 and 0 <= dc <= 6
                    m[rr][cc] = inside and (dr in (0, 6) or dc in (0, 6) or (2 <= dr <= 4 and 2 <= dc <= 4))
    finder(0, 0)
    finder(0, n - 7)
    finder(n - 7, 0)
    for i in range(8, n - 8):
        m[6][i] = m[i][6] = i % 2 == 0
    pos = _ALIGN[ver]
    last = len(pos) - 1
    for i, r in enumerate(pos):
        for j, c in enumerate(pos):
            if (i, j) in ((0, 0), (0, last), (last, 0)):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    m[r + dr][c + dc] = max(abs(dr), abs(dc)) != 1
    m[n - 8][8] = True                  # dark module
    for i in range(9):                  # reserve format areas
        if m[8][i] is None:
            m[8][i] = False
        if m[i][8] is None:
            m[i][8] = False
    for i in range(8):
        if m[8][n - 1 - i] is None:
            m[8][n - 1 - i] = False
        if m[n - 1 - i][8] is None:
            m[n - 1 - i][8] = False
    if ver >= 7:
        for i in range(6):
            for j in range(3):
                m[i][n - 11 + j] = False
                m[n - 11 + j][i] = False
    return m


def _place(m, cws, ver):
    n = len(m)
    reserved = [[v is not None for v in row] for row in m]
    bits = []
    for cw in cws:
        bits += _bits(cw, 8)
    i = 0
    up = True
    c = n - 1
    while c > 0:
        if c == 6:
            c -= 1
        rows = range(n - 1, -1, -1) if up else range(n)
        for r in rows:
            for cc in (c, c - 1):
                if not reserved[r][cc]:
                    m[r][cc] = bool(bits[i]) if i < len(bits) else False
                    i += 1
        up = not up
        c -= 2
    return reserved


def _apply(m, reserved, mask, ver):
    n = len(m)
    out = [row[:] for row in m]
    f = _MASKS[mask]
    for r in range(n):
        for c in range(n):
            if not reserved[r][c] and f(r, c):
                out[r][c] = not out[r][c]
    fb = _format_bits(mask)
    bit = [bool((fb >> i) & 1) for i in range(15)]
    for i in range(6):
        out[i][8] = bit[i]
    out[7][8] = bit[6]
    out[8][8] = bit[7]
    out[8][7] = bit[8]
    for i in range(9, 15):
        out[8][14 - i] = bit[i]
    for i in range(8):
        out[8][n - 1 - i] = bit[i]
    for i in range(8, 15):
        out[n - 15 + i][8] = bit[i]
    out[n - 8][8] = True
    if ver >= 7:
        vb = _version_bits(ver)
        for i in range(18):
            bit = bool((vb >> i) & 1)
            out[i // 3][n - 11 + i % 3] = bit
            out[n - 11 + i % 3][i // 3] = bit
    return out


def _penalty(m):
    n = len(m)
    score = 0
    for grid in (m, [list(col) for col in zip(*m)]):
        for row in grid:
            run, last = 0, None
            for v in row:
                if v == last:
                    run += 1
                else:
                    if run >= 5:
                        score += run - 2
                    run, last = 1, v
            if run >= 5:
                score += run - 2
            s = ''.join('1' if v else '0' for v in row)
            score += 40 * len(re.findall(r'(?=10111010000|00001011101)', s))
    for r in range(n - 1):
        for c in range(n - 1):
            if m[r][c] == m[r][c + 1] == m[r + 1][c] == m[r + 1][c + 1]:
                score += 3
    dark = sum(v for row in m for v in row)
    score += int(abs(dark * 100 / (n * n) - 50)) // 5 * 10
    return score


def matrix(text, mask=None):
    data = text.encode('utf-8') if isinstance(text, str) else text
    for ver in sorted(_M):
        total, ecn, b1, d1, b2, d2 = _M[ver]
        cap = b1 * d1 + b2 * d2
        if 4 + (8 if ver < 10 else 16) + 8 * len(data) <= cap * 8:
            break
    else:
        raise ValueError('text too long for a QR code')
    base = _base(ver)
    reserved = _place(base, _codewords(data, ver), ver)
    if mask is not None:
        if not isinstance(mask, int) or isinstance(mask, bool) or not 0 <= mask <= 7:
            raise ValueError('mask must be an integer between 0 and 7')
        return _apply(base, reserved, mask, ver)
    return min((_apply(base, reserved, k, ver) for k in range(8)), key=_penalty)


def svg(text, scale=4, border=4):
    m = matrix(text)
    n = len(m)
    size = (n + 2 * border) * scale
    parts = []
    for r in range(n):
        for c in range(n):
            if m[r][c]:
                parts.append('M%d %dh1v1h-1z' % (c + border, r + border))
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" '
            'shape-rendering="crispEdges"><rect width="100%%" height="100%%" fill="#fff"/>'
            '<path fill="#000" d="%s"/></svg>') % (n + 2 * border, n + 2 * border, size, size, ''.join(parts))
