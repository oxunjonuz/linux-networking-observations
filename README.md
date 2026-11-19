# Developer bundle — nftables payload writes and the UDP GRO/GSO path (F29–F74)

Two self-contained documents, built from the same measured findings:

| file | what it is |
|---|---|
| `NETFILTER_NFTABLES.md` | the nftables side, F29–F61: the payload store guards (`@ll`, `@nh`, `@th`, `@ih`), the frame envelopes that decide them (VLAN, Q-in-Q, PPPoE, tunnels, a device with no link header), and the checksum consequences |
| `UDP_GRO_GSO.md` | the UDP side, F62–F74: GSO segmentation, the GRO aggregate and the header it presents to a rule, the two ceilings that end aggregation, `skb_condense()`, the price a receive queue charges, and how the sender's buffer alignment sets the receiver's capacity |
| `BUGS_AND_TESTS.md` | the three-way triage: potential defects (observations only, never called confirmed bugs), expected Linux behaviour, and the invariant each finding would pin as a regression test |
| `HOW_TO_RUN.md` | host packages, kernel config, build and boot commands, and a table mapping every finding to its instrument, modes, runner, log marker and verifier |
| `CHECK.md` | what was verified in this bundle, with which script, and what was not |

## How a finding is written

Every finding has six labelled parts:

* **Claim** — the result in one paragraph.
* **Minimal reproduction** — the smallest arm that shows it (instrument, mode, rule or cell).
* **Run** — the command that produces the log and the marker to grep.
* **Expected** — what the kernel source says should happen.
* **Actual** — what was measured.
* **Limitations** — what the measurement does not cover.

The full evidence — tables, byte values, counters — follows under **Details**.

## What is in the bundle

| directory | contents |
|---|---|
| `code/full/` | the complete source of every instrument, gzipped; `code/vm/` the per-turn additions and build scripts; `code/tools/` the runners and the verifiers; `code/kernel/` the exact kernel config; `code/BINARIES.sha256` the hash of the binary that produced each log |
| `code/MANIFEST.sha256` | every shipped code file, hashed |
| `sources/records.json` | one record per finding: claim, reproduction, expected, actual, limitations, status, regression |
| `sources/sections/` | the full evidence of each finding |
| `sources/evidence/` | the finding's own source material (letter, `SUMMARY.md`, `summary.json`), against which every number in the documents is traced |
| `sources/triage.json` | the observation / expected / regression split and its wording |
| `src/` | the generators (`make_docs.py`, `make_code_bundle.py`) and the checks (`audit_bundle.py`, `audit_selftest.py`) |

`code/restore_tree.sh <dir>` unpacks the code into the tree layout the scripts
expect and rewrites their hard-coded root, so the commands in `HOW_TO_RUN.md`
work on any machine.

## Scope

Every rule discussed was installed by root in the initial user namespace;
nothing here crosses a privilege boundary and nothing here is a memory-safety
claim.  Each finding's **Limitations** line names what its measurement does not
cover.  The numbering follows the research log and therefore has a gap at F34,
which is not a separate finding.

The documents contain only results that survived the checks in `CHECK.md`.
