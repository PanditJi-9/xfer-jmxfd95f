#!/usr/bin/env python3
import argparse, gzip, hashlib, json, os, stat, sys, shutil

def sha256(p):
    h = hashlib.sha256()
    with open(p, 'rb', buffering=0) as f:
        while True:
            b = f.read(8 * 1024 * 1024)
            if not b: break
            h.update(b)
    return h.hexdigest()

def walk(root, skip_top=('lost+found',)):
    rows = {}
    def rec(d, rel):
        st = os.lstat(d)
        rows['.' if rel == '' else rel] = {'t': 'd', 'm': stat.S_IMODE(st.st_mode), 'u': st.st_uid, 'g': st.st_gid}
        try:
            with os.scandir(d) as it:
                entries = sorted(it, key=lambda e: e.name)
        except PermissionError:
            entries = []
        for e in entries:
            if rel == '' and e.name in skip_top: continue
            r = e.name if rel == '' else rel + '/' + e.name
            st = e.stat(follow_symlinks=False)
            m = stat.S_IMODE(st.st_mode)
            if stat.S_ISLNK(st.st_mode):
                rows[r] = {'t': 'l', 'm': m, 'u': st.st_uid, 'g': st.st_gid, 'h': os.readlink(e.path)}
            elif stat.S_ISDIR(st.st_mode):
                rec(e.path, r)
            elif stat.S_ISREG(st.st_mode):
                rows[r] = {'t': 'f', 'm': m, 'u': st.st_uid, 'g': st.st_gid, 's': st.st_size, 'h': sha256(e.path)}
            else:
                rows[r] = {'t': 'o', 'm': m, 'u': st.st_uid, 'g': st.st_gid}
    rec(root, '')
    return rows

def meta(x): return (x['m'], x['u'], x['g'])

def classify(mod, ota):
    if mod is None: return 'only_ota'
    if ota is None: return 'only_mod'
    if mod['t'] != ota['t']: return 'type'
    if mod['t'] == 'f':
        if mod['s'] != ota['s'] or mod['h'] != ota['h']: return 'content'
        return 'same' if meta(mod) == meta(ota) else 'metadata'
    if mod['t'] == 'l':
        if mod['h'] != ota['h']: return 'content'
        return 'same' if meta(mod) == meta(ota) else 'metadata'
    return 'same' if meta(mod) == meta(ota) else 'metadata'

def human(n):
    n = float(n)
    for u in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if abs(n) < 1024 or u == 'TiB': return f'{n:.2f} {u}'
        n /= 1024

def read_prop(path, key):
    try:
        with open(path, 'r', errors='replace') as f:
            for line in f:
                line = line.strip()
                if line.startswith(key + '='):
                    return line.split('=', 1)[1]
    except OSError:
        pass
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--partition', required=True)
    ap.add_argument('--mount', required=True)
    ap.add_argument('--manifest', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--copy-root')
    a = ap.parse_args()

    mod = {}
    with gzip.open(a.manifest, 'rt', encoding='utf-8') as f:
        for line in f:
            r = json.loads(line)
            mod[r['p']] = r

    if not os.path.isdir(a.mount):
        report = {'partition': a.partition, 'error': f'mount path missing: {a.mount}', 'summary': {'diff_total': 0}}
        base = a.out
        with open(base + '.json', 'w', encoding='utf-8') as f: json.dump(report, f, ensure_ascii=False, indent=1)
        with open(base + '.md', 'w', encoding='utf-8') as f: f.write(f'# {a.partition}\nERROR: mount path missing: {a.mount}\n')
        print(json.dumps(report, ensure_ascii=False))
        return 0

    ota = walk(a.mount)
    fingerprint = read_prop(os.path.join(a.mount, 'build.prop'), 'ro.vendor.build.fingerprint')
    if not fingerprint:
        fingerprint = read_prop(os.path.join(a.mount, 'etc/build.prop'), 'ro.vendor.build.fingerprint')

    counts = {k: 0 for k in ('only_ota', 'only_mod', 'content', 'metadata', 'type', 'same')}
    bytes_ = {'only_ota': 0, 'only_mod': 0, 'content_mod': 0, 'content_ota': 0}
    entries = []
    for p in sorted(set(mod) | set(ota)):
        m = mod.get(p); o = ota.get(p)
        st = classify(m, o)
        counts[st] += 1
        if st == 'same': continue
        if st == 'only_ota' and o and o['t'] == 'f': bytes_['only_ota'] += o.get('s', 0)
        if st == 'only_mod' and m and m['t'] == 'f': bytes_['only_mod'] += m.get('s', 0)
        if st == 'content':
            if o and o['t'] == 'f': bytes_['content_ota'] += o.get('s', 0)
            if m and m['t'] == 'f': bytes_['content_mod'] += m.get('s', 0)
        entries.append({
            'p': p, 'st': st,
            'mt': m['t'] if m else None, 'ot': o['t'] if o else None,
            'ms': m.get('s') if m else None, 'os': o.get('s') if o else None,
            'mm': m.get('m') if m else None, 'om': o.get('m') if o else None,
            'mu': m.get('u') if m else None, 'ou': o.get('u') if o else None,
            'mg': m.get('g') if m else None, 'og': o.get('g') if o else None,
            'mh': m.get('h') if m and m['t'] in ('f', 'l') else None,
            'oh': o.get('h') if o and o['t'] in ('f', 'l') else None,
        })

    copied = {'files': 0, 'bytes': 0}
    if a.copy_root:
        part_root = os.path.join(a.copy_root, a.partition)
        for e in entries:
            if e['st'] not in ('only_ota', 'content', 'type'): continue
            if e['ot'] not in ('f', 'l'): continue
            src = os.path.join(a.mount, e['p'])
            dst = os.path.join(part_root, e['p'])
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            try:
                if e['ot'] == 'f':
                    shutil.copyfile(src, dst)
                    os.chmod(dst, e['om'] & 0o7777)
                    copied['bytes'] += os.path.getsize(dst)
                else:
                    if os.path.lexists(dst): os.remove(dst)
                    os.symlink(e['oh'], dst)
                copied['files'] += 1
            except OSError as ex:
                print(f'COPY ERROR {e["p"]}: {ex}', file=sys.stderr)

    diff_total = counts['only_ota'] + counts['only_mod'] + counts['content'] + counts['metadata'] + counts['type']
    report = {
        'partition': a.partition,
        'ota_fingerprint': fingerprint,
        'summary': {**counts, 'diff_total': diff_total, **bytes_, 'mod_entries': len(mod), 'ota_entries': len(ota),
                    'copied_files': copied['files'], 'copied_bytes': copied['bytes']},
        'entries': entries,
    }
    with open(a.out + '.json', 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=1)
    with open(a.out + '.tsv', 'w', encoding='utf-8') as f:
        cols = ['status', 'path', 'mod_type', 'ota_type', 'mod_size', 'ota_size', 'mod_mode', 'ota_mode',
                'mod_uid', 'ota_uid', 'mod_gid', 'ota_gid', 'mod_hash', 'ota_hash']
        f.write('\t'.join(cols) + '\n')
        for e in entries:
            f.write('\t'.join('' if v is None else str(v) for v in (
                e['st'], e['p'], e['mt'], e['ot'], e['ms'], e['os'], e['mm'], e['om'],
                e['mu'], e['ou'], e['mg'], e['og'], e['mh'], e['oh'])) + '\n')
    with open(a.out + '.md', 'w', encoding='utf-8') as f:
        f.write(f'# {a.partition}\n\n')
        f.write(f'- OTA fingerprint: `{fingerprint}`\n')
        f.write(f'- mod entries: {len(mod)} | OTA entries: {len(ota)}\n')
        f.write(f'- only in OTA: {counts["only_ota"]} ({human(bytes_["only_ota"])})\n')
        f.write(f'- only in mod: {counts["only_mod"]} ({human(bytes_["only_mod"])})\n')
        f.write(f'- content differs: {counts["content"]} (mod {human(bytes_["content_mod"])} / OTA {human(bytes_["content_ota"])})\n')
        f.write(f'- metadata only: {counts["metadata"]} | type differs: {counts["type"]} | total diffs: {diff_total}\n')
        if a.copy_root:
            f.write(f'- copied originals: {copied["files"]} files ({human(copied["bytes"])})\n')
    print(json.dumps({'partition': a.partition, 'fingerprint': fingerprint, 'summary': report['summary']}, ensure_ascii=False))
    return 0

if __name__ == '__main__':
    sys.exit(main())
