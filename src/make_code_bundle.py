#!/usr/bin/env python3
"""make_code_bundle.py -- assemble dev-report/code/ from the working tree.

The bundle mirrors the tree the run scripts expect:

    code/vm/     the instrument additions, the full instruments (gzipped), the
                 build scripts, the initramfs builders, run_qemu.sh
    code/tools/  the per-finding runners, verifiers and their selftests

code/restore_tree.sh unpacks it into any directory and rewrites the hard-coded
ROOT of the scripts to that directory, so the same commands work outside
/work/kernel-sec.  Every copied file is hashed into code/MANIFEST.sha256.
"""
import os, re, glob, gzip, hashlib, shutil, json

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEV = os.path.join(ROOT, 'dev-report')
CODE = os.path.join(DEV, 'code')

def sha256(p):
    return hashlib.sha256(open(p, 'rb').read()).hexdigest()

def main():
    for sub in ('vm', 'tools', 'full'):
        os.makedirs(os.path.join(CODE, sub), exist_ok=True)
    copied, fulls, rows = [], set(), []
    for n in range(29, 75):
        run = f'tools/f{n}_run.sh'
        if not os.path.exists(os.path.join(ROOT, run)):
            continue
        copied.append(run)
        txt = open(os.path.join(ROOT, run), encoding='utf8', errors='replace').read()
        nums = re.findall(r'differ(\d+[a-z]?)', txt)
        if nums:
            num = nums[0]
            for pat in (f'vm/differ{num}_add.c', f'vm/build_f{n}_differ.sh',
                        f'vm/build_f{n}_differ.sh', f'vm/make_initramfs{num}.sh',
                        f'tools/verify{num}.py', f'tools/verify{num}_selftest.*',
                        f'tools/f{num}_summary.py', f'tools/f{n}_build_cfg.sh',
                        f'tools/f{n}_build_cfg.sh'):
                for p in glob.glob(os.path.join(ROOT, pat)):
                    copied.append(os.path.relpath(p, ROOT))
            fulls.add(num)
        if os.path.exists(os.path.join(ROOT, f'vm/build_f{n}_cfg.sh')):
            copied.append(f'vm/build_f{n}_cfg.sh')
        for pat in (f'tools/f{n}_*.sh', f'tools/f{n}_*.py', f'tools/audit_f{n}_doc.py',
                    f'tools/f{n}_battery.sh', f'tools/f{n}_splice.py'):
            for p in glob.glob(os.path.join(ROOT, pat)):
                copied.append(os.path.relpath(p, ROOT))
        v = f'tools/verify{n}.py'
        if os.path.exists(os.path.join(ROOT, v)):
            copied.append(v)
    copied = sorted(set(copied))
    # VM scripts that every runner depends on
    for extra in ('vm/run_qemu.sh',):
        if os.path.exists(os.path.join(ROOT, extra)):
            copied.append(extra)
    missing = [c for c in copied if not os.path.exists(os.path.join(ROOT, c))]
    assert not missing, missing
    for rel in copied:
        dst = os.path.join(CODE, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(os.path.join(ROOT, rel), dst)
        rows.append((os.path.join('code', rel), sha256(dst)))
    for num in sorted(fulls, key=lambda s: (int(re.sub(r'\D', '', s)), s)):
        src = os.path.join(ROOT, f'vm/differ{num}.c')
        assert os.path.exists(src), src
        dst = os.path.join(CODE, 'full', f'differ{num}.c.gz')
        with open(src, 'rb') as fi, gzip.GzipFile(dst, 'wb', 9, mtime=0) as fo:
            fo.write(fi.read())
        rows.append((os.path.join('code', f'full/differ{num}.c.gz'), sha256(dst)))
    man = os.path.join(CODE, 'MANIFEST.sha256')
    allrows = []
    for dirpath, _dirs, files in os.walk(CODE):
        for fn in files:
            if fn == 'MANIFEST.sha256':
                continue
            fullp = os.path.join(dirpath, fn)
            rel = os.path.relpath(fullp, DEV)
            allrows.append((rel, sha256(fullp)))
    allrows.sort()
    with open(man, 'w', encoding='utf8') as f:
        for rel, h in allrows:
            f.write(f'{h}  {rel}\n')
    rows = allrows
    print(f'{len(rows)} files, manifest sha256 {sha256(man)}')
    print('instruments:', ' '.join(sorted(fulls, key=lambda s: (int(re.sub(r"\D", "", s)), s))))

if __name__ == '__main__':
    main()
