#!/usr/bin/env python3
"""verify588_selftest.py -- can verify588.py still go red?

Each case makes ONE textual change in a copy of one log and requires the
verifier to exit 1 with a FAIL line -- not a traceback.  The `noop` case is
the unmutated copy: it must stay green, or every red below would mean
nothing.
"""
import os
import re
import subprocess
import sys

ROOT = "/work/kernel-sec"
L1 = f"{ROOT}/logs/f66_rep1.log"
L2 = f"{ROOT}/logs/f66_rep2.log"
VERIFY = f"{ROOT}/tools/verify588.py"
TMP = "/tmp/f66_selftest"


def run(p1, p2):
    r = subprocess.run([sys.executable, VERIFY, p1, p2],
                       capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def mutate_re(src, dst, pattern, new, count=1):
    txt = open(src, errors="replace").read()
    n = len(re.findall(pattern, txt))
    assert n == count, f"regex anchor {pattern[:60]!r}: {n} matches"
    open(dst, "w").write(re.sub(pattern, new, txt, count=count))


def mutate(src, dst, old, new, count=1):
    txt = open(src, errors="replace").read()
    n = txt.count(old)
    assert n == count, f"mutation anchor {old[:60]!r}: count {n} != {count}"
    open(dst, "w").write(txt.replace(old, new, count))


def arm_line(txt, mode, i):
    a = txt.index(f"=== MODE_BEGIN {mode} ===")
    b = txt.index(f"=== MODE_EXIT {mode}=")
    blk = txt[a:b]
    for ln in blk.splitlines():
        if ln.startswith(f"F588 ARM|i={i:02d}|"):
            return ln
    raise KeyError(i)


CASES = []


def case(name, old, new, count=1, frm=L1, keep=L2):
    CASES.append((name, old, new, count, frm, keep))


# ---- the byte cap, one clause at a time ---------------------------------
txt1 = open(L1, errors="replace").read()
cap = arm_line(txt1, "cap", 2)			# ku1023_u: the decisive arm
case("cap-ku1023_u-lgn", cap + "\n", cap.replace("|lgn=1|", "|lgn=2|") + "\n")
cap1 = arm_line(txt1, "cap", 1)			# ku1023_f
case("cap-ku1023_f-lg2",
     cap1 + "\n", cap1.replace("|lg2=1071|", "|lg2=1072|") + "\n")
cap11 = arm_line(txt1, "cap", 11)		# tf990: the last tail that merges
case("cap-tf990-lgplen",
     cap11 + "\n", cap11.replace("|lgplen=65487|", "|lgplen=65488|") + "\n")
cap12 = arm_line(txt1, "cap", 12)		# tf991: the first that does not
case("cap-tf991-lgn", cap12 + "\n", cap12.replace("|lgn=2|", "|lgn=1|") + "\n")
cap20 = arm_line(txt1, "cap", 20)		# tu976
case("cap-tu976-lgn", cap20 + "\n", cap20.replace("|lgn=2|", "|lgn=1|") + "\n")
cap14 = arm_line(txt1, "cap", 14)		# tu961: 65535 bytes, one frame
case("cap-tu961-an", cap14 + "\n", cap14.replace("|an=1|", "|an=64|") + "\n")
cap15 = arm_line(txt1, "cap", 15)		# tu962: 65536 bytes, sixty-four
case("cap-tu962-an", cap15 + "\n", cap15.replace("|an=64|", "|an=1|") + "\n")

# ---- the receive budget -------------------------------------------------
case("split-q131072-kept",
     "F587 RCV|i=07|att=0|n=39|",
     "F587 RCV|i=07|att=0|n=40|")
RE_CASES = []
RE_CASES.append(("split-q131072-err",
                 r"(F587 RCV\|i=07\|att=0\|[^\n]*?\|udp=39\|udperr=)25",
                 r"\g<1>26"))
case("split-q49152-kept",
     "F587 RCV|i=16|att=0|n=13|",
     "F587 RCV|i=16|att=0|n=14|")
case("split-q73728-kept",
     "F587 RCV|i=18|att=1|n=52|",
     "F587 RCV|i=18|att=1|n=51|")
RE_CASES.append(("split-queue-bytes",
                 r"(F587 RXQ\|i=02\|[^\n]*?:)00014000",
                 r"\g<1>00014100", 2))
case("split-drops-delta",
     "0000000000000000:0000 07 00000000:00017C00 00:00000000 00000000     0        0 307 2 000000003fb7188b 781",
     "0000000000000000:0000 07 00000000:00017C00 00:00000000 00000000     0        0 307 2 000000003fb7188b 780")
case("split-rbuf-eff",
     "F587 RBUF|rb=49152|eff=98304",
     "F587 RBUF|rb=49152|eff=98305")
RE_CASES.append(("split-conservation",
                 r"(F587 RCV\|i=05\|att=0\|[^\n]*?\|udp=1\|udperr=)63",
                 r"\g<1>62"))

# ---- what the wire carried ----------------------------------------------
case("tap-hop",
     "TAP|i=19|dev=y1|k=0|flen=1598|len=760|trunc=1|iplen=1544|hop=63|",
     "TAP|i=19|dev=y1|k=0|flen=1598|len=760|trunc=1|iplen=1544|hop=64|")
case("tap-flen",
     "dev=y1|k=0|flen=1598|len=760|trunc=1|iplen=1544|hop=63|uhlen=1544|uhck=fcc2",
     "dev=y1|k=0|flen=1599|len=760|trunc=1|iplen=1544|hop=63|uhlen=1544|uhck=fcc2")
case("tap-checksum",
     "TAP|i=19|dev=y1|k=0|flen=1598|len=760|trunc=1|iplen=1544|hop=63|"
     "uhlen=1544|uhck=fcc2",
     "TAP|i=19|dev=y1|k=0|flen=1598|len=760|trunc=1|iplen=1544|hop=63|"
     "uhlen=1544|uhck=fcc3")
case("tap-stat",
     "TAP|i=19|dev=y3a|k=0|flen=1598|len=760|trunc=1|iplen=1544|hop=63|"
     "uhlen=1544|uhck=fcc2|stat=9",
     "TAP|i=19|dev=y3a|k=0|flen=1598|len=760|trunc=1|iplen=1544|hop=63|"
     "uhlen=1544|uhck=fcc2|stat=1")
case("store-bytes",
     "|lgp0=a0a1a2a384858687|",
     "|lgp0=a0a1a2a484858687|")
case("two-witness",
     "TAP|i=19|dev=y1|k=0|flen=1598|len=760|trunc=1|iplen=1544|hop=63|"
     "uhlen=1544|uhck=fcc2|stat=9|hex=661ef5de9dd0968c7f04dc1986dd6004c0030608113ffd020000000000000000000000000011fd030000000000000000000000000092aa3c13880608fcc2a0a1a2a3",
     "TAP|i=19|dev=y1|k=0|flen=1598|len=760|trunc=1|iplen=1544|hop=63|"
     "uhlen=1544|uhck=fcc2|stat=9|hex=661ef5de9dd0968c7f04dc1986dd6004c0030608113ffd020000000000000000000000000011fd030000000000000000000000000092aa3c13880608fcc2a0a1a2a4")

# ---- provenance ---------------------------------------------------------
case("kernel-sha",
     "### sha256: 1efbc95771acb424ec876dfa5c32ff1e993f5230b840c27ff00125978cbd2033",
     "### sha256: 1efbc95771acb424ec876dfa5c32ff1e993f5230b840c27ff00125978cbd2034")
txt1 = open(L1, errors="replace").read()
m = re.search(r"### initrd sha256: ([0-9a-f]{64})", txt1)
case("initrd-sha", m.group(0), "### initrd sha256: " + "0" * 64)

# ---- the arm table ------------------------------------------------------
case("arm-name",
     "F588 ARM|i=02|name=ku1023_u|",
     "F588 ARM|i=02|name=ku1023_v|")
case("arm-pl",
     "F588 ARM|i=02|name=ku1023_u|src=s|dst=a|xg=u|n=64|pl=1023|",
     "F588 ARM|i=02|name=ku1023_u|src=s|dst=a|xg=u|n=64|pl=1024|")
case("arm-rcvbuf",
     "F588 ARM|i=16|name=q49152_lazy|src=s|dst=a|xg=f|n=64|pl=512|sh=-1|sl=0|"
     "store=0|off=0|len=0|hex=-|rc=0|cmdrc=0|exp=0|ch=1|ch0=1|agr=1|lgn=1|"
     "lgplen=32816|lg2=-1|lg6=8008|lgudp=aa3c13888008fcc2|lgp0=0081828384858687|"
     "lg2_6=-|lg2_udp=-|lg2_p0=-|win=800|rbq=49152|",
     "F588 ARM|i=16|name=q49152_lazy|src=s|dst=a|xg=f|n=64|pl=512|sh=-1|sl=0|"
     "store=0|off=0|len=0|hex=-|rc=0|cmdrc=0|exp=0|ch=1|ch0=1|agr=1|lgn=1|"
     "lgplen=32816|lg2=-1|lg6=8008|lgudp=aa3c13888008fcc2|lgp0=0081828384858687|"
     "lg2_6=-|lg2_udp=-|lg2_p0=-|win=800|rbq=49153|")


def main():
    os.makedirs(TMP, exist_ok=True)
    green, red, survived, crashed = 0, 0, [], []
    for idx, (name, old, new, count, frm, keep) in enumerate(CASES):
        dst = f"{TMP}/m{idx:02d}.log"
        try:
            mutate(frm, dst, old, new, count)
        except AssertionError as e:
            survived.append(f"{name}: ANCHOR {e}")
            continue
        rc, out = run(dst, keep)
        if "Traceback" in out:
            crashed.append(name)
        elif rc == 1 and "FAIL:" in out:
            if name.endswith("-noop"):
                green += 1
            else:
                red += 1
        elif rc == 0:
            if name.endswith("-noop"):
                green += 1
            else:
                survived.append(name)
        else:
            crashed.append(name)
    for idx, (name, pat, new, *cnt) in enumerate(RE_CASES):
        dst = f"{TMP}/r{idx:02d}.log"
        n = cnt[0] if cnt else 1
        try:
            mutate_re(L1, dst, pat, new, n)
        except AssertionError as e:
            survived.append(f"{name}: ANCHOR {e}")
            continue
        rc, out = run(dst, L2)
        if "Traceback" in out:
            crashed.append(name)
        elif rc == 1 and "FAIL:" in out:
            red += 1
        elif rc == 0:
            survived.append(name)
        else:
            crashed.append(name)
    # the noop: unmutated copies must pass
    rc, out = run(L1, L2)
    if rc == 0:
        green += 1
    else:
        survived.append("baseline is not green")
    print(f"cases={len(CASES) + len(RE_CASES)} red={red} green={green} "
          f"survived={len(survived)} crashed={len(crashed)}")
    for s in survived:
        print("SURVIVED:", s)
    for c in crashed:
        print("CRASH:", c)
    return 1 if (survived or crashed) else 0


if __name__ == "__main__":
    sys.exit(main())
