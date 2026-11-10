#!/usr/bin/env python3
"""Opt-in owner-media acceptance. Uses the OpenBF2 probe reader, never setup/DLLs.

All extracted inputs/reconstructions stay under BF2_RTP_SCRATCH. No installed
reference bytes are used as patch sources. See README for environment variables.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

# The external probe directory and all owner inputs remain read-only.
sys.dont_write_bytecode = True

AUTHORIZED = pathlib.Path(os.environ.get('BF2_RTP_SCRATCH', os.path.join(tempfile.gettempdir(), 'rtptool-bf2')))
REQUIRED = ('BF2_PATCH141', 'BF2_ISO', 'BF2_PATCH150', 'BF2_INSTALLED', 'BF2_PROBE_READER', 'BF2_GAP_REPORT')


def safe(root, name):
    parts = name.replace('\\', '/').split('/')
    if any(p in ('', '.', '..') or ':' in p for p in parts):
        raise ValueError('unsafe media path: ' + name)
    result = root.joinpath(*parts)
    if not result.resolve().is_relative_to(root.resolve()):
        raise ValueError('path escapes scratch')
    return result


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


def cabinet(fmt, path, iso=False):
    view = fmt.View(path)
    inv = fmt.iso_inventory(view) if iso else fmt.sfx_inventory(view)
    if not iso and (inv['end'] != view.size or inv['trailer_hex']):
        raise ValueError('SFX does not end exactly')
    views = {e['path'].replace('\\', '/').lower(): view.sub(e['offset'], e['size'])
             for e in inv['files'] if not e.get('directory')}
    prefix = '' if iso else 'disk1/'
    cab = fmt.Cabinet(views[prefix + 'data1.hdr'],
                      {n: views[prefix + f'data{n}.cab'] for n in (1, 2)})
    return view, inv, views, cab


def mapped(cab, destination, tag):
    result = {}
    for e in cab.files:
        if e['flags'] & 8:
            continue
        for group in e['groups']:
            dest = destination(tag, group, e['path'])
            if dest is not None:
                result[dest.lower()] = e
    return result


def extract(cab, entry, views, name, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('wb') as f:
        if entry['offset']:
            for block in cab.chunks(entry['index']):
                f.write(block)
        else:
            data = views[name].read()
            if len(data) != entry['size'] or hashlib.md5(data).hexdigest() != entry['md5']:
                raise ValueError('loose ISO size/MD5 mismatch: ' + name)
            f.write(data)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--rtptool', type=pathlib.Path, required=True)
    args = ap.parse_args()
    missing = [key for key in REQUIRED if not os.environ.get(key)]
    if missing:
        print('SKIP: missing ' + ', '.join(missing))
        return 0
    env = {key: pathlib.Path(os.environ[key]).resolve() for key in REQUIRED}
    scratch = pathlib.Path(os.environ.get('BF2_RTP_SCRATCH', str(AUTHORIZED))).resolve()
    if not scratch.is_relative_to(AUTHORIZED.resolve()):
        raise ValueError('scratch must be under ' + str(AUTHORIZED))
    scratch.mkdir(parents=True, exist_ok=True)
    run = pathlib.Path(tempfile.mkdtemp(prefix='phase2-', dir=scratch))
    print('Scratch:', run, flush=True)
    fmt = module('bf2_probe_formats', env['BF2_PROBE_READER'])
    # Import only the existing destination mapping, not the probe entrypoint.
    sys.path.insert(0, str(env['BF2_PROBE_READER'].parent))
    probe = module('bf2_probe_mapping', env['BF2_PROBE_READER'].with_name('probe.py'))
    view141 = fmt.View(env['BF2_PATCH141'])
    inv141 = fmt.sfx_inventory(view141)
    if inv141['end'] != view141.size or inv141['trailer_hex']:
        raise ValueError('1.41 SFX has unparsed bytes')
    patches, targets, bf2_targets = {}, set(), set()
    for e in inv141['files']:
        name = e['path'].replace('\\', '/').lower()
        product = name.split('/')[1]
        if name.endswith('.rtd'):
            rows = fmt.rtd_inventory(view141.read(e['offset'], e['size']))
            names = {r['path'].replace('\\', '/').lower() for r in rows if r['path']}
            targets.update(names)
            if product == 'bf2':
                bf2_targets = {r['path'].replace('\\', '/').lower() for r in rows if r['path'] and r['action'] in ('ADD', 'MODIFY')}
        if name.endswith('.rtp'):
            path = run / (product + '.rtp')
            path.write_bytes(view141.read(e['offset'], e['size']))
            patches[product] = path
    if set(patches) != {'bf2', 'bp1', 'bp2', 'xp1'}:
        raise ValueError('expected the four 1.41 payloads')
    summary = {'scratch': str(run), 'streams': {}, 'applications': {}}
    binary = str(args.rtptool.resolve())
    for product, path in patches.items():
        result = subprocess.run([binary, 'verify', str(path)], capture_output=True, text=True)
        (run / (product + '-verify.log')).write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(product + ' decode failed: ' + result.stderr)
        summary['streams'][product] = result.stdout.strip()
        print(product, result.stdout.strip(), flush=True)
    _, _, views_iso, cab_iso = cabinet(fmt, env['BF2_ISO'], iso=True)
    _, _, _, cab150 = cabinet(fmt, env['BF2_PATCH150'])
    map_iso, map150 = mapped(cab_iso, probe.destination, 'iso'), mapped(cab150, probe.destination, 'p150')
    reference = {p.relative_to(env['BF2_INSTALLED']).as_posix().lower(): p
                 for p in env['BF2_INSTALLED'].rglob('*') if p.is_file()}
    gap = {e['path'].lower() for e in json.loads(env['BF2_GAP_REPORT'].read_text())}
    derived_gap = (bf2_targets & reference.keys()) - map150.keys()
    if len(gap) != 125 or gap != derived_gap:
        raise ValueError(f'probe gap set differs from current inputs: report={len(gap)}, derived={len(derived_gap)}')
    sources, stage = run / 'disc', run / 'stage'
    sources.mkdir(); stage.mkdir()
    for name in sorted(targets & map_iso.keys()):
        target = safe(sources, name)
        extract(cab_iso, map_iso[name], views_iso, name, target)
        dest = safe(stage, name); dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(target, dest)
    print('Disc sources extracted:', len(targets & map_iso.keys()), flush=True)
    # Try every record, including optional products. Missing SF/booster bases are
    # retained as explicit diagnostics; only the stated 125-path set is acceptance.
    for product, path in patches.items():
        result = subprocess.run([binary, 'apply', str(path), '--source', str(sources), '--output', str(stage)], capture_output=True, text=True)
        (run / (product + '-apply.log')).write_text(result.stdout + result.stderr)
        summary['applications'][product] = {'exit': result.returncode, 'summary': result.stdout.strip().splitlines()[-1],
                                           'errors': result.stderr.splitlines()}
        print(product, summary['applications'][product]['summary'], flush=True)
    # Full 1.50 replacements overlay the stage; cabinet reader checks size/MD5.
    for name, entry in sorted(map150.items()):
        extract(cab150, entry, {}, name, safe(stage, name))
    print('1.50 full files overlaid:', len(map150), flush=True)
    matches, mismatches, missing_files = [], [], []
    for name in sorted(gap):
        actual = safe(stage, name)
        if not actual.is_file():
            missing_files.append(name)
        elif actual.read_bytes() == reference[name].read_bytes():
            matches.append(name)
        else:
            mismatches.append(name)
    summary.update(matched=len(matches), mismatched=len(mismatches), cannot_produce=missing_files,
                   mismatch_paths=mismatches, matched_paths=matches, overlay_count=len(map150))
    (run / 'acceptance.json').write_text(json.dumps(summary, indent=2) + '\n')
    (scratch / 'latest-run.txt').write_text(str(run) + '\n')
    (scratch / 'latest-acceptance.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(f'ACCEPTANCE: {len(matches)} matched, {len(mismatches)} mismatched, {len(missing_files)} cannot produce', flush=True)
    for name in mismatches + missing_files:
        print('  ' + name)
    return int(bool(mismatches or missing_files))


if __name__ == '__main__':
    sys.exit(main())
