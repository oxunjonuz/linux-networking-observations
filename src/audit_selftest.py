#!/usr/bin/env python3
"""audit_selftest.py -- prove that audit_bundle.py can go red.

Each mutation is applied to a copy of the bundle, one at a time; the audit must
exit non-zero *and* print its summary line (a crash is not a red).  The noop
copy must stay green.  The last mutation corrupts a shipped instrument source
and runs the audit with the rebuild check on, so the byte-identical rebuild is
proven to be a live check and not a comment.
"""
import os, sys, shutil, subprocess, tempfile, hashlib, gzip, json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run(root, rebuild=False):
    cmd = [sys.executable, os.path.join(root, 'src', 'audit_bundle.py')]
    if not rebuild:
        cmd.append('--no-rebuild')
    r = subprocess.run(cmd, cwd=root, capture_output=True, text=True)
    summary = '=== developer bundle audit:' in r.stdout
    red = '0 red' not in r.stdout.split('===')[-2] if summary else False
    return r.returncode, summary, r.stdout.strip().split('\n')[-1] if r.stdout.strip() else r.stderr[-200:]

def main():
    tmp = tempfile.mkdtemp(prefix='bundle_selftest_')
    dst = os.path.join(tmp, 'bundle')
    shutil.copytree(ROOT, dst, ignore=shutil.ignore_patterns('*.tar.gz', '__pycache__'))
    muts = []

    def mut(name, rel, old, new):
        p = os.path.join(dst, rel)
        t = open(p).read()
        assert old in t, (name, old[:40])
        open(p, 'w').write(t.replace(old, new, 1))
        muts.append((name, rel, t))

    results = []
    def check(name, expect_red, rebuild=False):
        rc, summary, tail = run(dst, rebuild)
        ok = (rc != 0) == expect_red and summary
        results.append((name, ok, rc, tail))
        for n, rel, orig in muts:
            open(os.path.join(dst, rel), 'w').write(orig)
        muts.clear()

    # 1 section removed
    p = os.path.join(dst, 'NETFILTER_NFTABLES.md')
    t = open(p).read()
    i = t.index('## F40 —'); j = t.index('## F41 —')
    open(p, 'w').write(t[:i] + t[j:])
    muts.append(('section removed', 'NETFILTER_NFTABLES.md', t))
    check('section removed', True)

    # 2 number changed (to one no evidence contains)
    mut('number changed', 'UDP_GRO_GSO.md', 'The byte cap that ends aggregation is 65536', 'The byte cap that ends aggregation is 999999')
    check('number changed', True)

    # 3 cyrillic inserted
    mut('cyrillic inserted', 'NETFILTER_NFTABLES.md', '# nftables payload writes', 'тест\n# nftables payload writes')
    check('cyrillic inserted', True)

    # 4 mail status inserted
    mut('mail status inserted', 'UDP_GRO_GSO.md', '# UDP GRO and GSO', 'STATUS: NOT SENT\n# UDP GRO and GSO')
    check('mail status inserted', True)

    # 5 superseded F72 law restored
    mut('superseded F72 law', 'UDP_GRO_GSO.md', 'PAGE_ALIGN(payload + page offset)', 'one page per payload')
    check('superseded F72 law', True)

    # 6 superseded F31 law restored
    mut('superseded F31 law', 'NETFILTER_NFTABLES.md', 'at the netdev ingress hook the guard is a constant', 'the netdev branch is dead code')
    check('superseded F31 law', True)

    # 7 label removed
    mut('label removed', 'UDP_GRO_GSO.md', '**Actual.** Six datagrams of 512 through the fraglist door', 'Six datagrams of 512 through the fraglist door')
    check('label removed', True)

    # 8 a triage row calls something a confirmed bug
    mut('confirmed bug claimed', 'BUGS_AND_TESTS.md', 'never a confirmed bug', 'is a confirmed bug')
    check('confirmed bug claimed', True)

    # 9 noop: same bytes, must stay green
    mut('noop', 'NETFILTER_NFTABLES.md', '# nftables payload writes', '# nftables payload writes')
    check('noop', False)

    # 10 instrument source corrupted, manifest updated: only the rebuild check may catch it
    name = 'code/full/differ551.c.gz'
    p = os.path.join(dst, name)
    src = gzip.decompress(open(p, 'rb').read())
    assert b'int main(' in src
    src = src.replace(b'int main(', b'int mainX(', 1)
    open(p, 'wb').write(gzip.compress(src, 9))
    man = os.path.join(dst, 'code', 'MANIFEST.sha256')
    mt = open(man).read().split('\n')
    h = hashlib.sha256(open(p, 'rb').read()).hexdigest()
    mt = [f'{h}  {name}' if l.endswith('  ' + name) else l for l in mt]
    open(man, 'w').write('\n'.join(mt))
    open(p + '.orig', 'wb').write(gzip.compress(gzip.decompress(open(p, 'rb').read()), 9))
    # run with rebuild on, then restore the whole code tree from the pristine copy
    rc, summary, tail = run(dst, rebuild=True)
    ok = rc != 0 and summary
    results.append(('corrupted instrument', ok, rc, tail))
    shutil.copyfile(os.path.join(ROOT, name), p)
    open(man, 'w').write(open(os.path.join(ROOT, 'code', 'MANIFEST.sha256')).read())

    bad = [r for r in results if not r[1]]
    for name, ok, rc, tail in results:
        print(f'{"RED as required " if ok else "NOT RED        "} {name:28s} rc={rc} {tail}')
    print(f'\n=== selftest: {len(results) - len(bad)}/{len(results)} behaved as required ===')
    shutil.rmtree(tmp, ignore_errors=True)
    return 1 if bad else 0

if __name__ == '__main__':
    sys.exit(main())
