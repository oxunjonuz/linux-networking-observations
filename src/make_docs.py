#!/usr/bin/env python3
"""make_docs.py -- build the two developer documents and the triage document.

Inputs, all inside this bundle:
  sources/records.json   one record per finding: claim, reproduction, expected,
                         actual, limitations, status, regression
  sources/meta.json      the instrument/modes/runner/checks line per finding
  sources/triage.json    the three-way triage: observation / expected behaviour
  sources/sections/F*.md the full evidence per finding

Outputs:
  NETFILTER_NFTABLES.md  F29-F61
  UDP_GRO_GSO.md         F62-F74
  BUGS_AND_TESTS.md      potential defects (observations only), expected Linux
                         behaviour, and the regression test each finding pins
"""
import json, os, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
S = os.path.join(ROOT, 'sources')

R = json.load(open(os.path.join(S, 'records.json')))
META = json.load(open(os.path.join(S, 'meta.json')))
TRIAGE = json.load(open(os.path.join(S, 'triage.json')))

def instrument(n):
    m = META[str(n)]
    x = re.search(r'`(code/(?:vm|full)/[^`]+)`', m)
    return x.group(1) if x else '(see meta)'

def modes(n):
    m = META[str(n)]
    x = re.search(r'\*modes ((?:`[^`]+`(?:, )?)+)\*', m)
    return x.group(1) if x else '—'

def build_script(n):
    p = os.path.join(ROOT, 'code', 'vm', f'build_f{n}_differ.sh')
    return f'bash vm/build_f{n}_differ.sh' if os.path.exists(p) else None

def run_line(n):
    b = build_script(n)
    parts = []
    if b:
        parts.append(f'`{b}`')
    parts.append(f'`bash code/tools/f{n}_run.sh`')
    return ' then '.join(parts) + f' — log marker `{R[str(n)]["marker"]}`; build and boot as in `HOW_TO_RUN.md` §2-5.'

HEAD = {
'nft': """# nftables payload writes: guards, envelopes and coordinates

Measurements of the nftables payload store, F29-F61.  Every finding states what
was measured, on which kernel, with which instrument and under which limit; the
instrument that produced the numbers is in `code/` and `HOW_TO_RUN.md` maps each
finding to its modes, runner and log marker.

Each finding is written in six parts:

* **Claim** -- the result in one paragraph.
* **Minimal reproduction** -- the smallest arm that shows it.
* **Run** -- the command that produces the log and the marker to grep.
* **Expected** -- what the kernel source says should happen.
* **Actual** -- what was measured.
* **Limitations** -- what the measurement does not cover.

The reproducing code is the instrument named in **Minimal reproduction**: its
source is in `code/`, the arm named there is the arm it runs, and the exact rule,
byte and counter are printed under **Details**.

The full evidence (tables, byte values, counters) follows under **Details**.

Scope: every rule was installed by root in the initial user namespace.  Nothing
here crosses a privilege boundary and nothing here is a memory-safety claim.
`BUGS_AND_TESTS.md` separates the findings that are potential defects
(observations only) from behaviour that Linux is designed to have, and lists the
invariant each finding would pin as a regression test.
""",
'udp': """# UDP GRO and GSO on the receive and forwarding path

Measurements of the UDP receive path, F62-F74: the aggregate a GRO door builds
and the header it presents to a rule, the two ceilings that end aggregation, the
price a receive queue charges, `skb_condense()`, and the two doors a forwarded
datagram can take into a queue.  The instrument that produced every number is in
`code/`; `HOW_TO_RUN.md` maps each finding to its modes, runner and log marker.

Each finding is written in six parts: **Claim**, **Minimal reproduction**,
**Run**, **Expected**, **Actual**, **Limitations**, followed by **Details** with
the full evidence.  The reproducing code is the instrument the finding names;
its source is in `code/`, and the exact arm, rule and byte are under **Details**.

Scope: every rule was installed by root in the initial user namespace.  The
numbers here are accounting and packet shape, not memory safety; a real NIC, TCP
GRO and tunnels were not measured unless a finding says otherwise.  See
`BUGS_AND_TESTS.md` for the three-way triage and the regression invariant of
each finding.
""",
}

def render_finding(n):
    r = R[str(n)]
    out = [f'## F{n} — {r["title"]}', '']
    out += [f'**Claim.** {r["claim"]}', '']
    out += [f'**Minimal reproduction.** {r["repro"]}', '']
    out += [f'**Run.** {run_line(n)}', '']
    out += [f'**Expected.** {r["expected"]}', '']
    out += [f'**Actual.** {r["actual"]}', '']
    out += [f'**Limitations.** {r["limits"]}', '']
    body = open(os.path.join(S, 'sections', f'F{n}.md')).read().strip()
    out += ['**Details.**', '', body, '']
    return '\n'.join(out)

def index_table(ids):
    out = ['| finding | subject | instrument | modes | runner |', '|---|---|---|---|---|']
    for n in ids:
        r = R[str(n)]
        out.append(f'| F{n} | {r["title"]} | `{instrument(n)}` | {modes(n)} | `{r["runner"]}` |')
    return '\n'.join(out)

def write_doc(doc):
    ids = sorted(n for n, r in R.items() if r['doc'] == doc)
    if not ids:
        return
    title = 'NETFILTER_NFTABLES.md' if doc == 'nft' else 'UDP_GRO_GSO.md'
    parts = [HEAD[doc], '', '## Index', '', index_table(ids), '']
    for n in ids:
        parts.append(render_finding(n))
    open(os.path.join(ROOT, title), 'w').write('\n'.join(parts).rstrip() + '\n')
    print(title, len(ids), 'findings')

write_doc('nft')
write_doc('udp')

# ---------------- BUGS_AND_TESTS.md ----------------
obs = sorted([n for n, r in R.items() if r['status'] == 'observation'], key=int)
exp = sorted([n for n, r in R.items() if r['status'] == 'expected'], key=int)
res = sorted([n for n, r in R.items() if r['status'] == 'result'], key=int)
assert len(obs) + len(exp) + len(res) == len(R), 'every finding must be triaged'

out = ["""# Potential defects, expected Linux behaviour, and regression tests

Two rules govern this file.

1. A row in section 1 is an **observation**, never a confirmed bug.  The
   measurement shows behaviour that differs from what the code's own guard, its
   declared field table, or the rule's coordinate promises; the last column
   names the evidence that would settle whether it is a defect.  Nothing here
   has been reported upstream, and every rule involved needs root in the initial
   user namespace.
2. A row in section 2 is behaviour that looks surprising but is what Linux is
   designed to do; the measurement is the anchor, not a complaint.

Section 3 lists, for every finding, the invariant a regression test would pin.
Each test can be run from this bundle: build the instrument and boot it as in
`HOW_TO_RUN.md`, then read the log marker named in the finding.

## 1. Potential defects — observations only

| finding | observation | why it is not called a confirmed bug | what would confirm it |
|---|---|---|---|"""]

for n in obs:
    t = TRIAGE[str(n)]
    out.append(f'| F{n} | {t["observes"]} | {t["not_confirmed"]} | {t["would_confirm"]} |')

out += ['', '## 2. Expected Linux behaviour', '',
        '| finding | behaviour | measured anchor |', '|---|---|---|']
for n in exp:
    t = TRIAGE[str(n)]
    out.append(f'| F{n} | {t["behaviour"]} | {t["anchor"]} |')

out += ['', '## 3. Regression tests', '',
        'Each row names the invariant a test should pin and the run that measures it. '
        'A test is expected to fail if the invariant moves; the numbers to compare '
        'against are in the finding\'s **Actual** line.', '',
        '| finding | invariant to pin | run |', '|---|---|---|']
for n in sorted(R, key=int):
    r = R[str(n)]
    out.append(f'| F{n} | {r["regression"]} | `{r["runner"]}` (marker `{r["marker"]}`) |')

out += ['', '## 4. What is not in this file', '',
        'No finding here is called a vulnerability, and no row in section 1 is called '
        'a confirmed bug: a confirmation would need a maintainer statement or a patch, '
        'neither of which this bundle contains.  Memory safety was not tested anywhere; '
        'the privilege boundary is measured in F57 and every other finding assumes the '
        'same root context.', '']
open(os.path.join(ROOT, 'BUGS_AND_TESTS.md'), 'w').write('\n'.join(out))
print('BUGS_AND_TESTS.md', len(obs), 'observations,', len(exp), 'expected,', len(res), 'results')
