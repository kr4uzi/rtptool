#!/usr/bin/env python3
"""Read-only, standard-library research prototype for the BF2 RTP0320 corpus.

No installer/DLL execution; metadata and reconstructed bytes stay in memory.
This is experimental format research, not a production patch installer.
"""

import argparse
import collections
import hashlib
import importlib.util
import json
import mmap
import pathlib

from rtp0320_codec import decompress


class Reader:
    def __init__(self, data, pos=0, end=None):
        self.data, self.pos = data, pos
        self.end = len(data) if end is None else end

    def take(self, n):
        p = self.pos
        self.skip(n)
        return bytes(self.data[p:self.pos])

    def skip(self, n):
        if n < 0 or self.pos + n > self.end:
            raise ValueError(f"out-of-range read at {self.pos:#x}: {n}")
        self.pos += n

    def uint(self, n):
        return int.from_bytes(self.take(n), "little")

    def vli(self):
        b = self.uint(1)
        count, mask = 0, 0x40
        while b & mask and mask:
            count += 1
            mask >>= 1
        if count > 4:
            raise ValueError("unsupported VLI width")
        v = b & 63 if not count else ((b & ((0x40 >> count) - 1)) << (8 * count)) | self.uint(count)
        return -v if b & 128 else v

    def string(self):
        n = self.uint(1)
        if n == 255:
            n = self.uint(2)
        d = self.take(n)
        if d and d[-1] != 0:
            raise ValueError(f"unterminated string at {self.pos - n:#x}")
        return d[:-1].decode("cp1252") if d else ""


def entry(r):
    pos = r.pos
    desc, check = r.take(24), r.take(10)
    times, name = r.take(8), r.string()
    return dict(offset=pos, descriptor=desc.hex(), size=int.from_bytes(desc[16:20], "little"),
                checksum=check.hex(), times=times.hex(), name=name)


def history(r, count):
    children = []
    for i in range(count):
        start, h = r.pos, r.uint(2)
        if h not in (0x2c4, 0x2c2, 0x2c3, 0x243):
            raise ValueError(f"unobserved child header {h:#x} at {start:#x}")
        kind = h & 15
        child = dict(offset=start, header=h, kind=kind)
        if kind == 3:
            child["src"] = [entry(r) for _ in range(r.vli())]
        elif kind in (2, 4):
            mod = r.uint(2) if kind == 4 else 0
            ns = r.vli() if kind == 4 and i == 0 else int(kind == 4)
            nd, expanded, size = r.vli(), r.uint(4), r.uint(4)
            sources = []
            for _ in range(ns):
                if i == 0:
                    sources.append(entry(r))
                else:
                    check = r.take(10).hex()
                    previous = children[-1].get("dst", [])
                    if len(previous) != 1 or previous[0]["checksum"] != check:
                        raise ValueError(f"history source inheritance fails at {r.pos:#x}")
                    sources.append(dict(previous[0], checksum=check, inherited=True))
            child.update(mod=mod, expanded=expanded, size=size, src=sources,
                         dst=[entry(r) for _ in range(nd)], data_offset=r.pos)
            child["prefix"] = bytes(r.data[r.pos:r.pos + min(size, 12)]).hex()
            r.skip(size)
        else:
            raise ValueError(f"unknown history type {kind} at {start:#x}")
        child["end"] = r.pos
        children.append(child)
    return children


def parse(data):
    r = Reader(data)
    if r.take(4) != b"K*\x20\x03":
        raise ValueError("expected RTP0320")
    flags, ext, options = r.uint(2), r.uint(4), r.uint(2)
    if flags != 0xb7e4 or ext != 0x10000 or options != 8:
        raise ValueError("unobserved header flags")
    header = dict(flags=flags, ext=ext, options=options,
                  opaque=r.take(12).hex(), attrs=r.uint(2), reserved=r.uint(2), cmd=r.uint(2),
                  file_count=r.uint(4), tail=r.uint(4))
    dirs = [r.string() for _ in range(r.uint(2))]
    records = []
    while True:
        start, h = r.pos, r.uint(2)
        kind = h >> 12
        if kind == 1:
            if h != 0x1000 or r.pos != r.end:
                raise ValueError(f"trailing data at {r.pos:#x}")
            break
        if h not in (0x5806, 0x4446, 0x4444, 0x2446, 0x3446, 0x3444):
            raise ValueError(f"unobserved record header {h:#x} at {start:#x}")
        opts = r.uint(4 if h & 0x800 else 2) if h & 2 else options
        name = r.string() if h & 4 else ""
        seek = (r.vli(), r.vli()) if opts & 0xc0 else None
        if seek and any(not 0 <= idx < len(dirs) for idx in seek):
            raise ValueError("directory index outside table")
        disk = r.vli() if h & 0x80 else None
        attrs = r.uint(2) if h & 0x100 else None
        paths = [r.string(), r.string()] if h & 0x200 and kind != 5 else []
        rec = dict(offset=start, header=h, kind=kind, options=opts, name=name,
                   dir_indices=seek, disk=disk, attrs=attrs, paths=paths)
        if kind == 5:
            size, count = r.uint(4), r.uint(2)
        rec["metadata"] = r.take(10).hex()
        if kind == 5:
            rec.update(history_size=size, history_count=count, children_offset=r.pos)
            end = r.pos + size
            if end > r.end:
                raise ValueError("history outside payload")
            sub = Reader(data, r.pos, end)
            rec["children"] = history(sub, count)
            if sub.pos != end:
                raise ValueError(f"history end {sub.pos:#x} != {end:#x}")
            r.pos = end
        elif kind == 3:
            rec["src"] = [entry(r) for _ in range(r.vli())]
        elif kind in (2, 4, 6):
            mod = r.uint(2) if kind == 4 else 0
            ns = r.vli() if kind == 4 else 0
            nd, expanded, size = r.vli(), r.uint(4), r.uint(4)
            rec.update(mod=mod, expanded=expanded, size=size,
                       src=[entry(r) for _ in range(ns)], dst=[entry(r) for _ in range(nd)])
            rec["data_offset"] = r.pos
            rec["prefix"] = data[r.pos:r.pos + min(size, 12)].hex()
            r.skip(size)
        else:
            raise ValueError(f"unknown type {kind} at {start:#x}")
        rec["end"] = r.pos
        records.append(rec)
    if header["file_count"] != len(records):
        raise ValueError("header file count disagrees with records")
    for rec in records:
        for c in rec.get("children", [rec]):
            if "prefix" in c and not c["prefix"].startswith("b59c"):
                raise ValueError("compressed payload missing magic")
            for e in c.get("src", []) + c.get("dst", []):
                if bytes.fromhex(e["checksum"])[:2] != bytes((e["size"] % 31, e["size"] % 30)):
                    raise ValueError("entry length accumulators disagree with size")
    return dict(header=header, dirs=dirs, records=records, eof=start, size=r.end)


def rolling(data, width):
    w, mask = 0, (1 << width) - 1
    for b in data:
        w ^= b
        w = ((w << 8) | (w >> (width - 8))) & mask
    return w


def validate(data, desc):
    check = bytes.fromhex(desc["checksum"])
    if len(data) != desc["size"]:
        raise ValueError("file size mismatch")
    if check[:2] != bytes((len(data) % 31, len(data) % 30)):
        raise ValueError("weak length checksum mismatch")
    for n, p in ((31, 2), (30, 6)):
        want = int.from_bytes(check[p:p + 4], "little") & ((1 << n) - 1)
        if rolling(data, n) != want:
            raise ValueError(f"{n}-bit checksum mismatch")


def apply(source, opcodes, size):
    """Bounded translation of the existing opcode interpreter; one source only."""
    r, out = Reader(opcodes), bytearray(size)
    pos = poke = 0
    gaps, templates, counts = [], [], collections.Counter()

    def gap(n):
        nonlocal pos
        if n < 0 or pos + n > size:
            raise ValueError("gap outside destination")
        if n:
            gaps.append((pos, n))
            pos += n

    def write(d):
        nonlocal pos
        if pos + len(d) > size:
            raise ValueError("write outside destination")
        out[pos:pos + len(d)] = d
        pos += len(d)

    def copy(off, n):
        if off < 0 or n < 0 or off + n > len(source):
            raise ValueError("copy outside source")
        write(source[off:off + n])

    def delta(seek, width, value):
        nonlocal poke
        poke += seek
        if poke < 0 or poke + width > size:
            raise ValueError("poke outside destination")
        old = int.from_bytes(out[poke:poke + width], "little")
        out[poke:poke + width] = ((old + value) & ((1 << (width * 8)) - 1)).to_bytes(width, "little")

    while r.pos < r.end:
        op = r.uint(1)
        counts[op] += 1
        if op == 1:
            if r.pos != r.end or gaps:
                raise ValueError("unconsumed opcodes or literal gaps")
            return bytes(out), counts
        if op == 2:
            if r.vli() != 0:
                raise ValueError("prototype supports only source zero")
            pos = poke = 0
        elif op in (3, 4):
            if op == 4:
                gap(r.vli())
            copy(r.vli(), r.vli())
        elif op == 5:
            gap(size - pos)
            for off, n in gaps:
                out[off:off + n] = r.take(n)
            gaps.clear()
        elif op == 6:
            delta(r.vli(), 1, r.uint(1))
        elif op in (7, 14, 15, 16):
            poke = 0
            width = {7: 1, 14: 1, 15: 2, 16: 4}[op]
            value, n = r.uint(width), r.vli()
            for _ in range(n):
                delta(r.vli(), width, value)
        elif op == 13:
            poke = 0
            for _ in range(r.vli()):
                delta(r.vli(), 1, r.uint(1))
        elif op == 8:
            templates.append((r.vli(), r.vli()))
        elif op in (9, 10):
            if op == 10:
                gap(r.vli())
            idx = r.vli()
            if not 0 <= idx < len(templates):
                raise ValueError("invalid template index")
            copy(*templates[idx])
        elif op in (11, 12):
            if op == 12:
                gap(r.vli())
            n = r.vli()
            if not 0 <= n <= size - pos:
                raise ValueError("invalid zero fill")
            write(bytes(n))
        elif 17 <= op <= 22:
            if op >= 20:
                gap(r.vli())
            pattern = r.take((1, 2, 4)[(op - 17) % 3])
            n = r.vli()
            if not 0 <= n <= size - pos:
                raise ValueError("invalid pattern fill")
            write((pattern * ((n + len(pattern) - 1) // len(pattern)))[:n])
        else:
            raise ValueError(f"unknown opcode {op:#x} at {r.pos - 1:#x}")
    raise ValueError("opcode stream has no END")


def installer_module(path):
    spec = importlib.util.spec_from_file_location("installer_formats", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def compare_rtd(parsed, rows):
    flat = [(rec["name"], c) for rec in parsed["records"] for c in rec.get("children", [rec])]
    rows = [r for r in rows if r["action"] != "HISTORY"]
    if len(flat) != len(rows):
        raise ValueError("RTD action count mismatch")
    obsolete = 0
    for (name, c), row in zip(flat, rows):
        action = {2: "ADD", 3: "DELETE", 4: "MODIFY"}[c["kind"]]
        if c["header"] == 0x243:
            # RTD retains the old MODIFY row; the binary has metadata only.
            action = "MODIFY"
            obsolete += 1
        if name.lower() != row["path"].lower() or action != row["action"]:
            raise ValueError("RTD action/path mismatch")
        if c["header"] != 0x243 and c.get("size", 0) != row["patch_size"]:
            raise ValueError("RTD compressed size mismatch")
    return dict(actions=len(flat), obsolete_modify_rows=obsolete)


def decode_small(data, parsed, limit):
    decoded = additions = scanned = 0
    total = 0
    ops, headers = collections.Counter(), collections.Counter()
    for rec in parsed["records"]:
        for c in rec.get("children", [rec]):
            if "size" not in c or c["expanded"] > limit:
                continue
            d, meta = decompress(bytes(data[c["data_offset"]:c["end"]]), c["expanded"])
            headers[str((meta["raw"], meta["reserved"], meta["initial"], meta["update"], meta["window"]))] += 1
            decoded += 1
            total += len(d)
            if c["kind"] == 2:
                validate(d, c["dst"][0])
                additions += 1
            elif c["src"][0]["size"] <= 2 * 1024 * 1024 and c["dst"][0]["size"] <= 2 * 1024 * 1024:
                # Zero source checks instruction syntax/bounds only, not content.
                _, counts = apply(bytes(c["src"][0]["size"]), d, c["dst"][0]["size"])
                ops.update(counts)
                scanned += 1
    return dict(streams=decoded, expanded_bytes=total, checked_additions=additions,
                syntax_checked_modifies=scanned, opcodes={hex(k): v for k, v in sorted(ops.items())},
                compression_headers=dict(headers))


def verify_samples(fmt, iso, installed, data, parsed):
    if iso is None or installed is None:
        raise ValueError("--verify-samples needs --iso and --installed")
    image = fmt.View(iso)
    files = {e["path"].lower(): image.sub(e["offset"], e["size"])
             for e in fmt.iso_inventory(image)["files"] if not e["directory"]}
    cab = fmt.Cabinet(files["data1.hdr"], {1: files["data1.cab"], 2: files["data2.cab"]})
    reference = {p.relative_to(installed).as_posix().lower(): p
                 for p in installed.rglob("*") if p.is_file()}
    samples = [("python/bf2/stats/endofround.py", "bf2/stats/endofround.py", "Python"),
               ("python/bf2/GameLogic.py", "bf2/GameLogic.py", "Python"),
               ("Admin/standard_admin/autobalance.py", "standard_admin/autobalance.py", "Admin"),
               ("mods/bf2/ClientArchives.con", "ClientArchives.con", "Mods - bf2"),
               ("mods/bf2/Levels/Wake_Island_2007/Info/favoriteMap.png", None, None),
               ("mods/bf2/MemeEdit.exe", None, None)]
    result = []
    for path, source_path, group in samples:
        rec = next(r for r in parsed["records"] if r["name"].replace("\\", "/").lower() == path.lower())
        source = None
        if source_path:
            e = next(e for e in cab.files if e["path"].lower() == source_path.lower() and group in e["groups"])
            source = cab.read(e["index"])
        nmodify = nadd = ndelete = 0
        for c in rec.get("children", [rec]):
            if c["kind"] == 3:
                # MemeEdit's historical DELETE is followed by a complete ADD.
                # No deletion of an input or reference file takes place.
                source = None
                ndelete += 1
                continue
            decoded, _ = decompress(bytes(data[c["data_offset"]:c["end"]]), c["expanded"])
            if c["kind"] == 4:
                if source is None:
                    raise ValueError("sample source missing")
                validate(source, c["src"][0])
                source, _ = apply(source, decoded, c["dst"][0]["size"])
                nmodify += 1
            else:
                source = decoded
                nadd += 1
            validate(source, c["dst"][0])
        expected = reference[path.lower()].read_bytes()
        if source != expected:
            raise ValueError(f"reference mismatch: {path}")
        result.append(dict(path=path, size=len(source), modify_steps=nmodify, add_steps=nadd,
                           historical_deletes=ndelete, sha256=hashlib.sha256(source).hexdigest(), match=True))
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sfx", type=pathlib.Path, required=True)
    ap.add_argument("--installer-reader", type=pathlib.Path, required=True)
    ap.add_argument("--json", action="store_true", help="print metadata only")
    ap.add_argument("--decode-limit", type=int, default=0, help="fully decode streams up to this expanded size")
    ap.add_argument("--verify-samples", action="store_true", help="compare six BF2 paths, entirely in memory")
    ap.add_argument("--iso", type=pathlib.Path)
    ap.add_argument("--installed", type=pathlib.Path)
    args = ap.parse_args()
    fmt = installer_module(args.installer_reader)
    view = fmt.View(args.sfx)
    inventory = fmt.sfx_inventory(view)
    if inventory["end"] != view.size or inventory["trailer_hex"]:
        raise ValueError("SFX did not parse to EOF")
    by_path = {e["path"].lower(): e for e in inventory["files"]}
    with args.sfx.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        for item in inventory["files"]:
            if item["name"].lower().endswith(".rtp"):
                # memoryview avoids copying the half-gigabyte BF2 payload.
                data = memoryview(mm)[item["offset"]:item["offset"] + item["size"]]
                try:
                    parsed = parse(data)
                    doc = by_path[item["path"].lower()[:-1] + "d"]
                    parsed["rtd_check"] = compare_rtd(parsed, fmt.rtd_inventory(view.read(doc["offset"], doc["size"])))
                    if args.decode_limit:
                        parsed["decode_check"] = decode_small(data, parsed, args.decode_limit)
                    if args.verify_samples and item["path"].lower() == "disk1\\bf2\\patch.rtp":
                        parsed["samples"] = verify_samples(fmt, args.iso, args.installed, data, parsed)
                finally:
                    data.release()
                if args.json:
                    print(json.dumps(dict(path=item["path"], **parsed)))
                else:
                    print(item["path"], parsed["size"], hex(parsed["eof"]),
                          dict(collections.Counter(r["kind"] for r in parsed["records"])))
                    for key in ("rtd_check", "decode_check", "samples"):
                        if key in parsed:
                            print(key, json.dumps(parsed[key]))


if __name__ == "__main__":
    main()
