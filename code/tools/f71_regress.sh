#!/bin/bash
# f71_regress.sh -- every earlier verifier must still be green on this tree,
# on its own logs.  Each one's exit code and summary line are recorded.
cd /work/kernel-sec || exit 1
: > logs/f71_regression.txt
bad=0
for v in 593 592 591 590 589 588 587 586 585 584 583 582 581 580 579 578 577 576 575 574 573 572 571 570 569; do
	f="tools/verify$v.py"
	[ -f "$f" ] || continue
	out=$(python3 "$f" 2>&1)
	rc=$?
	line=$(printf '%s\n' "$out" | grep -E "^(checks:|checks=|CHECKS )" | tail -1)
	[ $rc -ne 0 ] && bad=$((bad+1))
	printf 'verify%-4s rc=%d %s\n' "$v" "$rc" "$line" >> logs/f71_regression.txt
done
echo "=== regression done: $bad failing ===" >> logs/f71_regression.txt
cat logs/f71_regression.txt
exit $bad
