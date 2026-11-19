# What was checked in this bundle, and how

Three scripts, all in `src/`, all re-runnable, none of them needing anything
outside this directory:

```
python3 src/make_docs.py        # rebuilds the two documents and BUGS_AND_TESTS.md from sources/
python3 src/audit_bundle.py     # the checks below; exit 0 only if every check passes
python3 src/audit_selftest.py   # proves that the audit can go red
```

## 1. The audit, on this bundle

`python3 src/audit_bundle.py` → **1627 checks, 0 red**.

| family | checks | what it establishes |
|---|---|---|
| layout | 11 | every required file is present |
| records | 724 | 45 records: every field non-empty, every id present once, every runner exists, every marker matches its row in `HOW_TO_RUN.md`, 32 nftables + 13 UDP |
| document structure | 481 + 196 | per finding: title equals the record, the seven labels are present and non-empty, the details body is present, and the five record fields appear verbatim in the document |
| numbers | 1 | every numeric token in a finding's six fields and in its details appears in that finding's own evidence file (`sources/evidence/F<n>.txt`); hexadecimal tokens may match their bare or decimal form |
| triage | 82 | every finding is in exactly one of the three sections of `BUGS_AND_TESTS.md`, every observation and expected row has its wording, and nothing is called a confirmed bug |
| vocabulary | 81 | 27 forbidden patterns, 0 hits in each of the three documents: mail status, letter and owner references, research-log turns, working-tree paths, first person, and the three superseded statements |
| contradiction | 10 | the final wording of F31, F33, F68, F69, F72 and F73 is present, the superseded wording is absent, and the three `supersedes` links point the right way |
| cross finding | 13 | the same quantity carries the same value in every finding that states it (section 4) |
| language | 8 | no Cyrillic in any markdown or in the record files |
| manifest | 4 | 417 code files and 93 source files match their sha256 |
| rebuild | 3 | 45 instruments compile from `code/full/` to the byte-identical binary recorded in `code/BINARIES.sha256` |
| clean room | 11 | no read outside this directory, no absolute path in the text, every named runner and every code path present |

## 2. The audit's own selftest

`python3 src/audit_selftest.py` → **10/10 behaved as required**:

| mutation | result |
|---|---|
| one finding section removed | red: sections do not cover F29–F74 |
| a number changed to one no evidence contains | red: untraceable number |
| Cyrillic inserted | red: language |
| a mail-status line inserted | red: vocabulary |
| the superseded F72 law restored | red: record field no longer in the document |
| the superseded F31 law restored | red: superseded wording |
| one label removed | red: missing label |
| a triage row turned into "is a confirmed bug" | red: triage |
| an instrument source corrupted, its manifest hash updated | red: 44/45 byte-identical, compile failed |
| noop copy | green |

The corrupted-instrument mutation updates the manifest hash first, so the
manifest check stays green and only the rebuild check can catch it.

## 3. The three contradictions, and what the final text says

The superseded statement is **removed**, not annotated: each pair below now
carries only the version that survived the later measurement.

| pair | earlier statement | final statement in both documents | checked by |
|---|---|---|---|
| F31 / F33 | the netdev branch is dead code | the netdev family has an ingress hook, where the guard is a constant, and an egress hook, where the branch is live and dispatches on `skb->protocol`; the egress columns equal the `ip4` and `arp` columns cell by cell | forbidden phrase absent; the final wording required in F31 and F33 |
| F68 / F69 | the fraglist byte cap is unreachable at 64 datagrams | a length change ends the flow after one datagram, so the cap is reachable only with equal lengths; 40 datagrams of 1637 bytes split 39 + 1 on the fraglist door, and the 20-byte price difference is 127·1280/64 against 126·1280/64, arithmetic rather than a price | forbidden phrase absent; the equal-length cell required in F68 and F69 |
| F72 / F73 | the charge is one page per payload | the charge is `PAGE_ALIGN(payload + page offset)`: 512 bytes cost 5056 at page offset 0 and 9152 at offset 3600, 5000 bytes cost 9152 and 13248 | forbidden sentence absent; the final law and the three placements required in F72 and F73 |

## 4. Cross-finding consistency

The audit requires the same quantity to appear in every finding that states it:

* 65536 — F65, F66, F68 and F69 (the two GRO ceilings and the two merge points);
* H = 48 and the 40-byte family shift — F66 and F68;
* 1280 and 2304 — F67 and F69 (one datagram's price and the aggregate's total);
* `(2k-1)*s` total against the head's `N * s` — F67 and F69;
* 5056 and 9152 — F72, F73 and F74 (the same charge read at the queue by three instruments);
* `CHECKSUM_PARTIAL` — F60 and F61; `uh->check` — F63 and F64.

## 5. Clean room

The archive was extracted into an empty directory and `src/audit_bundle.py` was
run there: same 1627 checks, 0 red, including the 45 byte-identical rebuilds.
The audit records every path it opens and refuses to read anything outside the
bundle directory; the documents contain no absolute path, and every runner they
name is in `code/`.

## 6. What this does not prove

* The documents are a re-presentation of the measurements.  Number
  traceability and the structure checks bind every statement to the finding's
  own material; they do not re-derive the physics.
* The verifiers in `code/tools/` were written against the original working tree
  (logs, kernel sources, initramfs) and are shipped for reading; the audit does
  not run them.
* No kernel was booted during the audit.  The numbers are those recorded in the
  logs of the named kernels; the instrument sources are pinned by the manifest
  and by the byte-identical rebuild.
* Nothing here is called a vulnerability, and no observation is called a
  confirmed bug.

The kernel image every boot printed is
`1efbc95771acb424ec876dfa5c32ff1e993f5230b840c27ff00125978cbd2033`, and
`code/kernel/config-7.3.4-T563` is the configuration it was built with.
