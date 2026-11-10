"""Research translation of src/codec.rs, with a bit-at-a-time Huffman reader.

Kept separate so the 0320 framing can be reviewed independently of the codec.
"""


class Bits:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def read(self, n):
        if self.pos + n > len(self.data) * 8:
            raise ValueError("truncated compressed stream")
        value = 0
        for _ in range(n):
            value = value << 1 | ((self.data[self.pos // 8] >> (7 - self.pos % 8)) & 1)
            self.pos += 1
        return value


class Tree:
    def u16(self, p):
        return int.from_bytes(self.m[p:p + 2], "little")

    def s16(self, p):
        x = self.u16(p)
        return x - 65536 if x & 32768 else x

    def w16(self, p, v):
        assert 0 <= p <= len(self.m) - 2
        self.m[p:p + 2] = (v & 65535).to_bytes(2, "little")

    def u32(self, p):
        assert 0 <= p <= len(self.m) - 4
        return int.from_bytes(self.m[p:p + 4], "little")

    def w32(self, p, v):
        assert 0 <= p <= len(self.m) - 4
        self.m[p:p + 4] = (v & 0xffffffff).to_bytes(4, "little")

    def __init__(self, esc_bits, levels, initial, update):
        alpha = 1 << esc_bits
        gc, st, slot = 0x34, levels * 2 + 0x34, levels * 6 + 0x38
        weight = levels * 6 + 0x40 + alpha * 4
        limit = weight + 4 + alpha * 2
        self.m = bytearray(limit + 0xc0 + 0x100)
        for p in (0x32, 2, 0):
            self.w16(p, initial)
        for p in (0x30, 0x2e, 0x2c):
            self.w16(p, update)
        self.w16(6, esc_bits)
        self.w16(4, levels)
        for p, v in ((0x0c, gc), (0x20, st), (0x1c, slot), (0x18, weight),
                     (0x14, limit), (0x10, limit)):
            self.w32(p, v)
        self.w16(0x0a, 1)
        self.w16(8, 1)
        self.w16(gc, 2)
        self.w32(st, slot)
        for i in range(1, levels + 1):
            self.w32(st + i * 4, slot + 8)
        base = weight + alpha * 2
        self.w32(slot, base)
        for i in range(1, alpha + 2):
            self.w32(slot + i * 4, base + 2)
        for i in range(alpha):
            self.w16(weight + i * 2, 0x8000)
        self.w16(0x24, alpha)
        self.limits(0)

    def limits(self, start):
        gc, lim = self.u32(0x0c), self.u32(0x10)
        s3 = 2 if not start else self.s16(lim + (start - 1) * 8) * 2
        for level in range(start, self.u16(4)):
            s4 = s3 - self.s16(gc + level * 2)
            for k, v in enumerate((s4, s4 * 2, s4 * 4, s4 * 16)):
                self.w16(lim + level * 8 + k * 2, v)
            s3 = s4 * 2

    def add(self, sym):
        w, slot, gc, st = (self.u32(p) for p in (0x18, 0x1c, 0x0c, 0x20))
        self.w16(w + sym * 2, 1)
        n = self.u16(8)
        self.w32(slot + n * 4, w + sym * 2)
        n += 1
        self.w16(8, n)
        if n == 2:
            return 0
        groups, num = self.u16(0x0a), self.u16(4)
        if groups < num:
            u = groups - 1
            self.w16(0x0a, groups + 1)
        else:
            u = groups - 2
            while self.s16(gc + u * 2) == 0:
                u -= 1
        self.w16(gc + u * 2, self.s16(gc + u * 2) - 1)
        self.w16(gc + (u + 1) * 2, self.s16(gc + (u + 1) * 2) + 2)
        self.w32(st + (u + 1) * 4, self.u32(st + (u + 1) * 4) - 4)
        for j in range(u + 2, num + 1):
            self.w32(st + j * 4, self.u32(st + j * 4) + 4)
        return u

    def rebuild(self):
        slot, st, gc = (self.u32(p) for p in (0x1c, 0x20, 0x0c))
        n, upd, num = self.u16(8), self.s16(0x2c), self.u16(4)
        self.w16(0x2c, upd - 1)
        maxw = 0
        for i in range(n):
            p = self.u32(slot + i * 4)
            v = self.u16(p)
            if ((upd - 1) & 65535) == 0:
                v >>= 1
                self.w16(p, v)
            maxw = max(maxw, v)
        if maxw:
            mask = 0x8000
            while not maxw & mask:
                mask = (mask >> 1) | 0x8000
            la = 0
            while la < n:
                if not self.u16(self.u32(slot + la * 4)) & mask:
                    j, ins = la + 1, la
                    if n <= j:
                        break
                    u5 = ins
                    while j < n:
                        pp, u5 = slot + j * 4, ins
                        p9 = self.u32(pp)
                        if self.u16(p9) & mask:
                            u5 = ins + 1
                            pc = self.u32(slot + ins * 4)
                            self.w32(slot + ins * 4, p9)
                            self.w32(pp, pc)
                        j, ins = j + 1, u5
                    if u5 != la:
                        la = u5 - 1
                    nm = mask >> 1
                    mask = nm | 0x8000
                    if nm & 1:
                        break
                else:
                    la += 1
        la, groups, moved = 0, self.u16(0x0a), 0
        last = groups - 1
        # This loop mirrors the group rebalance in src/codec.rs.
        while la < groups:
            pg, p2 = gc + la * 2, st + la * 4
            g = self.u16(pg)
            if not g:
                la += 1
                continue
            p1 = self.u32(p2 + 4)
            first = self.u16(self.u32(self.u32(p2)))
            wl = self.u16(self.u32(p1 - 4))
            wl2 = self.u16(self.u32(p1 - 8))
            if g < 3 or num - 1 == la or first < wl + wl2:
                p16, acc, j = p2 + 4, wl, la + 2
                while j < groups:
                    p4 = st + j * 4
                    acc = (acc - self.s16(self.u32(self.u32(p4)))) & 65535
                    wn = self.u16(self.u32(self.u32(p4) + 4))
                    if self.u16(gc + j * 2) > 1 and (acc & 32768 or acc < wn):
                        break
                    j += 1
                if j >= groups:
                    la += 1
                    continue
                self.w16(pg, self.s16(pg) - 1)
                moved += 1
                la += 1
                self.w32(p16, self.u32(p16) - 4)
                self.w16(gc + la * 2, self.s16(gc + la * 2) + 2)
                self.w32(p2 + 8, self.u32(p2 + 8) + 4)
                if la < j - 1:
                    span = j - 1 - la
                    la += span
                    for _ in range(span):
                        self.w32(p16 + 8, self.u32(p16 + 8) + 4)
                        p16 += 4
                self.w16(gc + la * 2, self.s16(gc + la * 2) + 1)
                self.w32(p16 + 4, self.u32(p16 + 4) + 4)
                self.w16(gc + 2 + la * 2, self.s16(gc + 2 + la * 2) - 2)
                if self.s16(gc + last * 2) == 0:
                    groups -= 1
                    self.w16(0x0a, groups)
                    last -= 1
                la = 0
            else:
                moved += 1
                self.w16(pg - 2, self.s16(pg - 2) + 1)
                self.w16(pg, self.s16(pg) - 3)
                self.w16(gc + 2 + la * 2, self.s16(gc + 2 + la * 2) + 2)
                self.w32(p2, self.u32(p2) + 4)
                self.w32(p2 + 4, self.u32(p2 + 4) - 8)
                if last == la:
                    groups += 1
                    self.w16(0x0a, groups)
                    last += 1
                la = 0
        if moved < 16:
            if moved < 8 and self.u16(0x2e) != 1:
                self.w16(2, self.u16(2) << 1)
                self.w16(0x2c, self.u16(0x2c) >> 1)
                self.w16(0x2e, self.u16(0x2e) >> 1)
        else:
            self.w16(2, self.u16(0x32))
            self.w16(0x2e, self.u16(0x30))
        self.w16(0, self.u16(2))
        if not self.u16(0x2c):
            self.w16(0x2c, self.u16(0x2e))

    def decode(self, bits):
        val, lim = 0, self.u32(0x10)
        for level in range(self.u16(4)):
            val = val * 2 + bits.read(1)
            threshold = self.u16(lim + level * 8)
            if val >= threshold:
                table = self.u32(self.u32(0x20) + level * 4)
                p = self.u32(table + (val - threshold) * 4)
                sym = (p - self.u32(0x18)) // 2
                break
        else:
            raise ValueError("invalid Huffman code")
        w = self.u32(0x18) + sym * 2
        self.w16(w, self.u16(w) + 1)
        self.w16(0, self.s16(0) - 1)
        if not self.u16(0):
            self.rebuild()
            self.limits(0)
        if sym == self.u16(0x24):
            raw = bits.read(self.u16(6))
            level = self.add(raw)
            self.limits(level)
            return raw
        return sym


def decompress(data, expected, limit=256 * 1024 * 1024):
    """Require the terminator and exact declared expanded size; never truncate."""
    if expected > limit:
        raise ValueError("expanded stream exceeds research memory limit")
    bits = Bits(data)
    if bits.read(16) != 0xb59c:
        raise ValueError("bad diff magic")
    raw, reserved = bits.read(8), bits.read(8)
    initial, update, window = bits.read(12), bits.read(12), bits.read(4)
    if not initial or not update or window not in (0, 8):
        raise ValueError("unobserved compression options")
    low = 7 if window == 8 else 6
    literal = None if raw else Tree(8, 16, initial, update)
    length, distance = Tree(6, 12, initial, update), Tree(6, 12, initial, update)
    out = bytearray()
    while True:
        if not bits.read(1):
            out.append(bits.read(8) if raw else literal.decode(bits))
        else:
            lo = bits.read(low)
            dist = (distance.decode(bits) << low) | lo
            if not dist:
                break
            n = length.decode(bits) & 127
            back = dist + 1
            for _ in range(n):
                out.append(out[-back] if len(out) >= back else 0)
        if len(out) > expected:
            raise ValueError(f"expanded stream exceeds declared size {expected}")
    if len(out) != expected:
        raise ValueError(f"expanded size {len(out)} != {expected}")
    if len(data) * 8 - bits.pos >= 8:
        raise ValueError("whole bytes remain after compressed terminator")
    return bytes(out), dict(raw=raw, reserved=reserved, initial=initial, update=update,
                            window=window, bits=bits.pos)
