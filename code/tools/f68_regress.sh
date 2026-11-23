#!/bin/bash
# f67_regress.sh -- every earlier verifier must still be green on this tree.
cd /work/kernel-sec || exit 1
: > logs/f68_regression.txt
for v in 590 589 588 587 586 585 584 583 582 581 580 579 578 577 576 575 574 573 572 571 570 569; do
	f="tools/verify$v.py"
	[ -f "$f" ] || continue
	out=$(python3 "$f" 2>&1)
	rc=$?
	line=$(printf '%s\n' "$out" | grep -E "^checks=" | head -1)
	printf 'verify%s rc=%d %s\n' "$v" "$rc" "$line" >> logs/f68_regression.txt
done
echo "=== regression done ===" >> logs/f68_regression.txt
