#!/bin/bash
# verify575_selftest.sh -- every one-field mutation must turn verify575.py red,
# and `noop` must leave it green.  A crash is not a caught mutation.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
pass=0; fail=0

base() {  # base <name>
	F53_LOGDIR="$TMP/$1" python3 tools/verify575.py > "$TMP/$1.out" 2>&1
	echo $?
}

mkdir -p "$TMP/base"
python3 tools/f575_mutate.py noop logs "$TMP/base" >/dev/null || exit 1
rc=$(base base)
if [ "$rc" = 0 ] && grep -q "fails=0" "$TMP/base.out"; then
	echo "PASS baseline green"; pass=$((pass+1))
else
	echo "FAIL baseline rc=$rc"; tail -3 "$TMP/base.out"; fail=$((fail+1))
fi

for m in noop g6 ch u6n i6in deliv disc hwheader indev l2len vproto vtci \
	 taplen tapbyte payload flags vid u6len frame warn nowarn arm plen hwlen; do
	mkdir -p "$TMP/$m"
	if ! python3 tools/f575_mutate.py "$m" logs "$TMP/$m" >/dev/null 2>&1; then
		echo "SKIP $m (mutator could not apply)"; fail=$((fail+1)); continue
	fi
	rc=$(base "$m")
	if [ "$m" = "noop" ]; then
		if [ "$rc" = 0 ]; then echo "PASS noop stays green"; pass=$((pass+1));
		else echo "FAIL noop went red"; fail=$((fail+1)); fi
	else
		if [ "$rc" = 1 ] && grep -qi "traceback" "$TMP/$m.out"; then
			echo "FAIL $m red by crash"; fail=$((fail+1))
		elif [ "$rc" = 1 ]; then
			echo "PASS $m red ($(grep -c '^FAIL' "$TMP/$m.out") checks)"; pass=$((pass+1))
		else
			echo "FAIL $m survived (rc=$rc)"; fail=$((fail+1))
		fi
	fi
done
echo "selftest: pass=$pass fail=$fail"
[ "$fail" = 0 ]
