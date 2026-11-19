# Verification and limits

The original bundle’s audit checked the correspondence between its records, generated reports, evidence files and test programs. These are the results recorded in its verification report.

| Check | Recorded result | What it establishes |
| --- | --- | --- |
| Bundle audit in a clean directory | 1,627 checks passed | The extracted bundle met its structural, cross-reference and consistency checks. |
| Test program rebuilds | 45 byte-identical rebuilds | The rebuilt programs matched the recorded binary hashes. |
| Audit self-tests | 10 of 10 behaved as expected | Deliberately altered inputs triggered the corresponding failures, and the unchanged control passed. |
| Measurement coverage | 32 nftables records and 13 UDP records | The report accounts for 45 distinct research records. |

A matching binary hash identifies a program. It does not independently reproduce a kernel observation. The clean-directory audit did not boot a kernel or rerun the packet experiments. Numeric traceability means a number appeared in the associated evidence. Establishing that it measures the claimed effect requires examining the experiment itself.

The public reports group related findings and retain the original record identifiers. The F74 table transcribes queue counts from the measurement record. Its limits are effective kernel buffer limits, in bytes. Results from the same-host UDP path cannot establish what a physical interface or a remote receiver would observe.
