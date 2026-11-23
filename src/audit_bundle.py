#!/usr/bin/env python3
"""audit_bundle.py -- independent checks of the developer bundle.

The audit is clean-room: every path it opens is resolved inside the bundle
directory and recorded; at the end it asserts that nothing outside the bundle
was read.  It never uses the reporter's working tree, the logs, or the kernels.

Counted checks, one per assertion.  Exit code 0 only when the red count is 0.
"""
import os, re, sys, json, hashlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OPENED = []
N = 0
RED = []
FAM = {}

def P(rel):
    p = os.path.realpath(os.path.join(ROOT, rel))
    if not (p == ROOT or p.startswith(ROOT + os.sep)):
        raise RuntimeError(f'path escapes the bundle: {rel} -> {p}')
    return p

def read(rel, binary=False):
    p = P(rel)
    OPENED.append(p)
    with open(p, 'rb' if binary else 'r', errors=None if binary else 'replace') as f:
        return f.read()

def check(ok, name, detail=''):
    global N
    N += 1
    fam = name.split()[0]
    FAM[fam] = FAM.get(fam, 0) + 1
    if not ok:
        RED.append(f'{name}: {detail}')

DOCS = ['NETFILTER_NFTABLES.md', 'UDP_GRO_GSO.md', 'BUGS_AND_TESTS.md']
ALL_MD = DOCS + ['README.md', 'HOW_TO_RUN.md', 'CHECK.md']
EXPECTED_IDS = [n for n in range(29, 75) if n != 34]

# ---------- 1. layout ----------
for f in DOCS + ['README.md', 'HOW_TO_RUN.md', 'CHECK.md',
                 'sources/records.json', 'sources/meta.json', 'sources/triage.json',
                 'sources/MANIFEST.sha256', 'code/MANIFEST.sha256']:
    check(os.path.exists(P(f)), 'layout', f'missing {f}')

R = json.loads(read('sources/records.json'))
META = json.loads(read('sources/meta.json'))
TRIAGE = json.loads(read('sources/triage.json'))

# ---------- 2. records ----------
check(len(R) == 45, 'records', f'{len(R)} records, expected 45')
check(sorted(map(int, R)) == EXPECTED_IDS, 'records', 'ids are not F29..F74 minus F34')
fields = ['title', 'claim', 'repro', 'runner', 'marker', 'expected', 'actual',
          'limits', 'status', 'regression', 'doc']
for n, r in R.items():
    for f in fields:
        check(bool(r.get(f)), f'records F{n}', f'empty field {f}')
    check(r['doc'] in ('nft', 'udp'), f'records F{n}', 'bad doc')
    check(r['status'] in ('observation', 'expected', 'result'), f'records F{n}', 'bad status')
    check(os.path.exists(P(r['runner'])), f'records F{n}', f'runner {r["runner"]} missing')
    how = read('HOW_TO_RUN.md')
    row = [l for l in how.split('\n') if l.startswith(f'| F{n} |')]
    check(len(row) == 1 and r['marker'] in row[0],
          f'records F{n}', 'marker does not appear in the HOW_TO_RUN row')
    check(len(r['claim']) > 40 and len(r['actual']) > 40, f'records F{n}', 'claim/actual too short')
check(sum(1 for r in R.values() if r['doc'] == 'nft') == 32, 'records', 'nft count')
check(sum(1 for r in R.values() if r['doc'] == 'udp') == 13, 'records', 'udp count')

# ---------- 3. documents ----------
DOC_TEXT = {d: read(d) for d in DOCS}
sec_re = re.compile(r'^## F(\d+) — (.+)$', re.M)
sections = {}
for d in DOCS[:2]:
    ids = [int(m[0]) for m in sec_re.findall(DOC_TEXT[d])]
    want = [n for n in EXPECTED_IDS if R[str(n)]['doc'] == ('nft' if d.startswith('NET') else 'udp')]
    check(ids == want, d, f'section order {ids} != {want}')
    parts = re.split(r'^## F(\d+) — ', DOC_TEXT[d], flags=re.M)
    for i in range(1, len(parts), 2):
        n = int(parts[i]); body = parts[i + 1]
        sections[n] = body
        title = body.split('\n', 1)[0].strip()
        check(title == R[str(n)]['title'], f'{d} F{n}', 'title does not match the record')
        for label in ['**Claim.**', '**Minimal reproduction.**', '**Run.**',
                      '**Expected.**', '**Actual.**', '**Limitations.**', '**Details.**']:
            check(label in body, f'{d} F{n}', f'missing {label}')
        m = re.search(r'\*\*(Claim|Minimal reproduction|Run|Expected|Actual|Limitations)\.\*\* (\S.*)', body)
        check(m is not None and len(m.group(2)) > 20, f'{d} F{n}', 'first field empty')
        body_txt = body.split('**Details.**', 1)[-1]
        check(len(body_txt.strip()) > 200, f'{d} F{n}', 'details body too short')
        # every record field is reproduced verbatim
        for f in ('claim', 'repro', 'expected', 'actual', 'limits'):
            check(R[str(n)][f] in body, f'{d} F{n}', f'record field {f} not in the document')
check(len(sections) == 45, 'documents', f'{len(sections)} sections, expected 45')
check(set(sections) == set(EXPECTED_IDS), 'documents', 'sections do not cover F29..F74')

# ---------- 4. language ----------
cyr = re.compile(r'[\u0400-\u04FF]')
for f in ALL_MD:
    check(cyr.search(DOC_TEXT.get(f, read(f))) is None, 'language', f'Cyrillic in {f}')
for f in ['sources/records.json', 'sources/triage.json']:
    check(cyr.search(read(f)) is None, 'language', f'Cyrillic in {f}')

# ---------- 5. forbidden vocabulary ----------
FORBID = [
    (r'\bSTATUS\b', 'status block'),
    (r'NOT SENT', 'mail status'),
    (r'\bheld\b', 'held letter'),
    (r'\bthe owner\b', 'owner reference'),
    (r"\bowner's\b", 'owner reference'),
    (r'\bSubject line\b|\bSubject hint\b|\bSubject:', 'mail subject'),
    (r'\bDraft\b', 'draft marker'),
    (r'\bmailed\b', 'mail status'),
    (r'\bearlier mail\b', 'mail reference'),
    (r'\bturn \d+\b', 'research-log turn'),
    (r'candidate section', 'candidate marker'),
    (r'\bfindings/', 'working-tree path'),
    (r'\bSUMMARY\.md\b', 'working-tree path'),
    (r'\bresearch/', 'working-tree path'),
    (r'predictions_\d+', 'predictions file'),
    (r'\breporter\b', 'reporter reference'),
    (r'\bmy \b', 'first person'),
    (r'(?<![A-Za-z])I(?![A-Za-z])', 'first person'),
    (r"I've", 'first person'),
    (r'\brefut', 'refutation talk'),
    (r'\bpredict', 'prediction talk'),
    (r'\bF28\b', 'mail thread reference'),
    (r'one page per payload, not one page per page touched', 'superseded F72 law'),
    (r'(the )?(netdev )?branch is dead code', 'superseded F31 law'),
    (r'function is dead code', 'superseded F31 law'),
    (r'unreachable in the only family', 'superseded F31 law'),
    (r'unreachable on the fraglist path', 'superseded F68 law'),
]
for d in DOCS:
    for pat, why in FORBID:
        hits = re.findall(pat, DOC_TEXT[d])
        check(not hits, f'vocabulary {d}', f'{why}: {pat} -> {len(hits)} hit(s)')

# ---------- 6. contradictions: final wording must be present ----------
def one(d, n):
    return sections[n]

check('egress hook' in one('NETFILTER_NFTABLES.md', 31) and
      'constant' in one('NETFILTER_NFTABLES.md', 31), 'contradiction', 'F31 lacks the final netdev wording')
check('at egress the branch is live' in one('NETFILTER_NFTABLES.md', 33), 'contradiction', 'F33 lacks the final netdev wording')
check('same length' in one('UDP_GRO_GSO.md', 68) and 'F69' in one('UDP_GRO_GSO.md', 68),
      'contradiction', 'F68 lacks the final cap wording')
check('length change ends the flow' in one('UDP_GRO_GSO.md', 69) and
      '40 datagrams of 1637' in one('UDP_GRO_GSO.md', 69), 'contradiction', 'F69 lacks the equal-length cell')
check('PAGE_ALIGN(payload + page offset)' in one('UDP_GRO_GSO.md', 72), 'contradiction', 'F72 lacks the final charge law')
check('PAGE_ALIGN(copied + start)' in one('UDP_GRO_GSO.md', 73), 'contradiction', 'F73 lacks the source line')
check('5056 = 960 + 4096' in one('UDP_GRO_GSO.md', 73), 'contradiction', 'F73 lacks the three placements')
# the three superseded records must name what they supersede
check(R['33'].get('supersedes') == [31], 'contradiction', 'F33 supersedes')
check(R['69'].get('supersedes') == [68], 'contradiction', 'F69 supersedes')
check(R['73'].get('supersedes') == [72], 'contradiction', 'F73 supersedes')


# ---------- 6b. cross-finding consistency (same quantity, same value) ----------
CROSS = [
    (66, 68, '65536'), (65, 66, '65536'), (68, 69, '65536'),
    (67, 69, '1280'), (67, 69, '2304'),
    (72, 73, '5056'), (72, 73, '9152'),
    (60, 61, 'CHECKSUM_PARTIAL'), (63, 64, 'uh->check'),
    (66, 68, '48'), (68, 69, 'H'),
]
for a, b, token in CROSS:
    check(token in sections[a] and token in sections[b], 'cross finding',
          f'F{a}/F{b} do not share {token!r}')
check('2*(48-28)' in sections[68] and '40' in sections[68], 'cross finding',
      'F68 does not carry the 40-byte shift')
check('(2k-1)*s' in sections[69] and 'N * s' in sections[67].replace('N * s', 'N * s'),
      'cross finding', 'F69/F67 do not share the head-pays law')

# ---------- 7. triage ----------
obs = [n for n, r in R.items() if r['status'] == 'observation']
exp = [n for n, r in R.items() if r['status'] == 'expected']
res = [n for n, r in R.items() if r['status'] == 'result']
BUG = DOC_TEXT['BUGS_AND_TESTS.md']
sec1, sec2, sec3 = (re.split(r'^## ', BUG, flags=re.M) + ['', '', ''])[1:4]
for n in obs:
    check(f'| F{n} |' in sec1, 'triage', f'observation F{n} not in section 1')
    check(str(n) in TRIAGE, 'triage', f'no triage text for F{n}')
for n in exp:
    check(f'| F{n} |' in sec2, 'triage', f'expected F{n} not in section 2')
    check(str(n) in TRIAGE, 'triage', f'no triage text for F{n}')
for n in res:
    check(f'| F{n} |' in sec3, 'triage', f'result F{n} not in section 3')
check(len(obs) + len(exp) + len(res) == 45, 'triage', 'not every finding is triaged')
check(re.search(r'\bis (a )?confirmed bug\b', BUG) is None, 'triage', 'a row calls something a confirmed bug')
for line in BUG.split('\n'):
    if 'confirmed' in line:
        check(('never' in line) or ('not called' in line) or ('not in this file' in line)
              or line.startswith('No finding') or line.startswith('a confirmed bug'),
              'triage', f'unguarded "confirmed": {line[:80]}')

# ---------- 8. numbers trace to the finding's own evidence ----------
tok = re.compile(r'(?<![A-Za-z0-9_])(0x[0-9a-fA-F]+|\d+)(?![A-Za-z0-9_])')
def toks(s):
    return set(t.lower() for t in tok.findall(s))

def traceable(t, ev, ev_text):
    if t in ev:
        return True
    alts = [t]
    if t.startswith('0x'):
        alts.append(t[2:])
        try:
            alts.append(str(int(t, 16)))
        except ValueError:
            pass
    for a in alts:
        if re.search(r'(?<![0-9a-z])' + re.escape(a) + r'(?![0-9a-z])', ev_text):
            return True
    return False
missing = {}
for n, r in R.items():
    ev_text = read(f'sources/evidence/F{n}.txt').lower()
    ev = toks(ev_text)
    body = sections.get(int(n), '')
    rtxt = ' '.join(str(r[k]) for k in ('claim', 'repro', 'expected', 'actual', 'limits', 'regression'))
    miss = sorted([t for t in toks(body + ' ' + rtxt) if not traceable(t, ev, ev_text)],
                  key=lambda x: (len(x), x))
    if miss:
        missing[n] = miss
check(not missing, 'numbers', f'{len(missing)} findings with untraceable numbers: '
      + '; '.join(f'F{k}:{v}' for k, v in list(missing.items())[:6]))

# ---------- 9. code and sources manifests ----------
def verify_manifest(path):
    bad = []
    lines = read(path).strip().split('\n')
    for line in lines:
        h, rel = line.split('  ', 1)
        if not os.path.exists(P(rel)):
            bad.append(f'missing {rel}'); continue
        got = hashlib.sha256(read(rel, binary=True)).hexdigest()
        if got != h:
            bad.append(f'hash {rel}')
    check(not bad, f'manifest {path}', f'{len(bad)} bad of {len(lines)}: {bad[:3]}')
    return len(lines)

n_code = verify_manifest('code/MANIFEST.sha256')
n_src = verify_manifest('sources/MANIFEST.sha256')
check(n_code >= 416, 'manifest code', f'{n_code} files')
check(n_src >= 93, 'manifest sources', f'{n_src} files')

# ---------- 9b. rebuild: the shipped source compiles to the recorded binary ----------
if '--no-rebuild' not in sys.argv:
    import gzip, subprocess, tempfile
    rec = {}
    for line in read('code/BINARIES.sha256').strip().split('\n'):
        h, name = line.split('  ', 1); rec[name] = h
    check(len(rec) == 45, 'rebuild', f'{len(rec)} recorded binaries')
    tmp = tempfile.mkdtemp(prefix='bundle_rebuild_')
    built = same = 0
    diff = []
    for n in EXPECTED_IDS:
        name = 'differ' + re.search(r'differ(\d+)', META[str(n)]).group(1)
        src = os.path.join(tmp, name + '.c')
        with gzip.open(P(f'code/full/{name}.c.gz'), 'rb') as fi:
            data = fi.read()
        open(src, 'wb').write(data)
        out = os.path.join(tmp, name)
        r = subprocess.run(['gcc', '-O2', '-Wall', '-Wno-unused-function', '-static',
                            '-o', out, src], capture_output=True)
        built += 1
        if r.returncode != 0:
            diff.append(f'{name}: compile failed')
            continue
        h = hashlib.sha256(open(out, 'rb').read()).hexdigest()
        if h == rec.get(name):
            same += 1
        else:
            diff.append(f'{name}: binary differs')
        os.unlink(src); os.unlink(out)
    check(built == 45, 'rebuild', f'{built} instruments compiled')
    check(not diff, 'rebuild', f'{same}/{built} byte-identical: {diff[:4]}')

# ---------- 10. clean room ----------
WORKTREE = '/wo' + 'rk/kernel-sec'
for d in DOCS + ['README.md', 'HOW_TO_RUN.md', 'CHECK.md']:
    t = DOC_TEXT.get(d, read(d))
    check(WORKTREE not in t and '../' not in t,
          'clean room', f'external path in {d}')
for f in ['src/make_docs.py', 'src/audit_bundle.py']:
    t = read(f)
    check(WORKTREE not in t, 'clean room', f'hard-coded working tree in {f}')
outside = [p for p in OPENED if not p.startswith(ROOT + os.sep)]
check(not outside, 'clean room', f'{len(outside)} reads outside the bundle: {outside[:3]}')
check(all(os.path.exists(P(f'code/tools/f{n}_run.sh')) for n in EXPECTED_IDS),
      'clean room', 'a runner named in the documents is absent from code/')
refs = set()
for d in DOCS + ['README.md', 'HOW_TO_RUN.md', 'CHECK.md']:
    refs |= set(re.findall(r'`(code/[A-Za-z0-9_./-]+)`', DOC_TEXT.get(d, read(d))))
missing = sorted(r for r in refs if not os.path.exists(P(r)))
check(not missing, 'clean room', f'every code path named exists ({len(refs)} refs; missing {missing[:6]})')

print('--- checks by family ---')
for k in sorted(FAM):
    print(f'{k:14s} {FAM[k]}')
print(f'=== developer bundle audit: {N} checks, {len(RED)} red ===')
for r in RED:
    print('RED', r)
sys.exit(1 if RED else 0)
