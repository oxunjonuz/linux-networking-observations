# How to run

Everything in `NETFILTER_NFTABLES.md` and `UDP_GRO_GSO.md` was produced by one program shape: a static C program
(`differN`) that creates its own network namespaces, installs rules over
netlink, sends frames, and prints one `F<instrument> ...` line per measured cell;
it runs inside a disposable QEMU guest booted with its own kernel and an
initramfs that contains busybox, the program, and nftables 1.1.7. Nothing on the
host kernel is used for the experiment, and the host needs no privileges beyond
running QEMU.

## 1. What the host needs

| tool | what it is for | version used here |
|---|---|---|
| `gcc` | builds the instrument, statically | Debian 14.2.0 |
| `qemu-system-x86_64` | boots the guest (TCG, no KVM needed) | 10.0.13 |
| `cpio`, `gzip` | pack the initramfs | any |
| a static `busybox` | the guest's shell and coreutils | `/usr/bin/busybox` |
| nftables 1.1.7 built static | the guest's rule client | `nft.static` |
| the kernel image | booted by QEMU | `bzImage`, 7.3.4 + the config in `code/kernel/` |

`code/kernel/config-7.3.4-T563` is the exact configuration of the kernel used
for F41–F74 (`CONFIG_KPROBE_EVENTS=y`, `CONFIG_NF_TABLES{,_ARP,_BRIDGE,_NETDEV}=y`,
`CONFIG_VXLAN=y`, `CONFIG_NET_IPIP=y`, `CONFIG_PPP=y`, `CONFIG_PPPOE=y`,
`CONFIG_NETFILTER_NETLINK_LOG=y`). Build a 7.3.4 tree with it if you want your
own image; the image used here has `sha256 1efbc95771acb424ec876dfa5c32ff1e993f5230b840c27ff00125978cbd2033`
and every boot prints it.

## 2. Unpack the code

```
bash code/restore_tree.sh /tmp/ksec
cd /tmp/ksec
```

This produces `/tmp/ksec/vm` and `/tmp/ksec/tools`, with the hard-coded `ROOT` of
every script rewritten to `/tmp/ksec`.

## 3. Build an instrument

```
bash vm/build_f74_differ.sh                 # -> vm/build/differ596
sha256sum vm/build/differ596
```

The build is deterministic: the binary must hash to
`1c7c9e596a621360d3d5830fdf3f4568ef71801e9e0fceb9c95411cc07d4ae91`, which is the
binary that produced the logs behind F74. Each finding's instrument is
accumulated from the previous ones — `build_f74_differ.sh` renames the `main()`
of `differ595.c` to `f595_entry` and appends `differ596_add.c`, whose own `main()`
handles the new modes and falls back to the old entry for the rest — so the last
instrument in a chain can run every earlier mode of that chain as well.

## 4. Build the initramfs and boot

```
bash vm/make_initramfs596.sh vm/build/differ596 q h        # -> vm/initramfs596.cpio.gz
INITRD=/tmp/ksec/vm/initramfs596.cpio.gz TIMEOUT=7200 \
     bash vm/run_qemu.sh <bzImage> logs/f74_rep1.log
grep '^F596 ' logs/f74_rep1.log
```

`make_initramfs596.sh` writes an `/init` that runs `/root/repro <mode>` for each
mode given on its command line and prints `=== MODE_BEGIN <mode> ===` /
`=== MODE_EXIT <mode>=<rc> ===` around it. The two paths it copies from
(`/usr/bin/busybox`, `<tree>/src/dl23/nftables-1.1.7/src/nft.static`) are the
only host-specific lines in it.

`run_qemu.sh` boots with `console=ttyS0 rdinit=/init panic=-1 nokaslr loglevel=7`
and appends a header with the kernel and initrd hashes, then a footer with the
`VM_BOOT_OK` count and any `KASAN`/`BUG:`/`Oops` lines. Two boots of the same
image are the norm: every finding in the report was measured in two, and the
numbers agree between them.

## 5. Read the result

Each `F<instrument>` line is one measured cell or one summary of an arm:

```
F596 BOOT|mode=q|argc=1|limit=0
F596 Q|arm=q64_a0_R38|i=0|att=0|R=38400|charge=5056|kept=7|rmem=35392|err=57
```

The verifier of each finding recomputes these numbers from the log, the kernel
image and the instrument source, and exits non-zero on any mismatch. The
verifiers are included in `code/tools/` so that a reader can see exactly what
was recomputed; they expect the reporter's working tree (logs, kernel source,
initramfs) and are not self-contained.

## 6. Which instrument and which modes belong to which finding

| finding | instrument | modes | runner | log marker | verifier |
|---|---|---|---|---|---|
| F29 | `differ551` | — | `f29_run.sh` | `F551` | `verify551.py` |
| F30 | `differ552` | — | `f30_run.sh` | `F552` | `verify552.py` |
| F31 | `differ553` | — | `f31_run.sh` | `F553` | `verify553.py` |
| F32 | `differ555` | — | `f32_run.sh` | `F555` | `verify555.py` |
| F33 | `differ556` | `f556bare`, `f556e`, `f556nd` | `f33_run.sh` | `F556` | `verify556.py` |
| F35 | `differ557` | `f557bytes`, `f557diag`, `f557diag10`, `f557diag11`, `f557diag2`, `f557diag3`, `f557diag4`, `f557diag5`, `f557diag6`, `f557diag7`, `f557diag8`, `f557diag9`, `f557grid`, `f557tun`, `f557verdict` | `f35_run.sh` | `F557` | `verify557.py` |
| F36 | `differ558` | `f558bytes`, `f558ipv6`, `f558vlan`, `f558why` | `f36_run.sh` | `F558` | `verify558.py` |
| F37 | `differ559` | `f559chain`, `f559feat`, `f559ih`, `f559probe`, `f559smoke`, `f559wire`, `f559wiroff`, `f559wiron` | `f37_run.sh` | `F559` | `verify559.py` |
| F38 | `differ560` | `f560arp`, `f560drop`, `f560ndeg`, `f560ndin`, `f560recv` | `f38_run.sh` | `F560` | `verify560.py` |
| F39 | `differ561` | `f561far`, `f561ll`, `f561meta`, `f561ndin`, `f561unlock`, `f561xmit` | `f39_run.sh` | `F561` | `verify561.py` |
| F40 | `differ562` | `f562ctl`, `f562ih`, `f562pair`, `f562qarp`, `f562rd`, `f562val` | `f40_run.sh` | `F562` | `verify562.py` |
| F41 | `differ563` | `f563arp`, `f563ctl`, `f563ih`, `f563pair`, `f563ppp`, `f563rd`, `f563st` | `f41_run.sh` | `F563` | `verify563.py` |
| F42 | `differ564` | `f564b`, `f564l`, `f564v` | `f42_run.sh` | `F564` | `verify564.py` |
| F43 | `differ565` | `f565c`, `f565g`, `f565t`, `f565v` | `f43_run.sh` | `F565` | `verify565.py` |
| F44 | `differ566` | `diag`, `dp`, `gd`, `md`, `rf`, `td`, `tm` | `f44_run.sh` | `F566` | `verify566.py` |
| F45 | `differ567` | `dbg`, `diag`, `md`, `mp`, `nh`, `rd`, `td`, `tf`, `xc`, `xf` | `f45_run.sh` | `F567` | `verify567.py` |
| F46 | `differ568` | `cs`, `ctl`, `ld`, `ll`, `nh`, `rd`, `th` | `f46_run.sh` | `F568` | `verify568.py` |
| F47 | `differ569` | `iso` | `f47_run.sh` | `F569` | `verify569.py` |
| F48 | `differ570` | `ppp6e`, `th6` | `f48_run.sh` | `F570` | `verify570.py` |
| F49 | `differ571` | `ctl`, `rd`, `tapf`, `wr` | `f49_run.sh` | `F571` | `verify571.py` |
| F50 | `differ572` | — | `f50_run.sh` | `F572` | `verify572.py` |
| F51 | `differ573` | — | `f51_run.sh` | `F573` | `verify573.py` |
| F52 | `differ574` | — | `f52_run.sh` | `F574` | `verify574.py` |
| F53 | `differ575` | — | `f53_run.sh` | `F575` | `verify575.py` |
| F54 | `differ576` | `warn`, `xf` | `f54_run.sh` | `F576` | `verify576.py` |
| F55 | `differ577` | `pcp` | `f55_run.sh` | `F577` | `verify577.py` |
| F56 | `differ578` | `ad`, `br` | `f56_run.sh` | `F578` | `verify578.py` |
| F57 | `differ579` | `priv`, `probe` | `f57_run.sh` | `F579` | `verify579.py` |
| F58 | `differ580` | `bounds` | `f58_run.sh` | `F580` | `verify580.py` |
| F59 | `differ581` | `guard` | `f59_run.sh` | `F581` | `verify581.py` |
| F60 | `differ582` | `opt`, `part` | `f60_run.sh` | `F582` | `verify582.py` |
| F61 | `differ583` | `fwd` | `f61_run.sh` | `F583` | `verify583.py` |
| F62 | `differ584` | `gso` | `f62_run.sh` | `F584` | `verify584.py` |
| F63 | `differ585` | `aggr` | `f63_run.sh` | `F585` | `verify585.py` |
| F64 | `differ586` | `geom` | `f64_run.sh` | `F586` | `verify586.py` |
| F65 | `differ587` | `cap`, `flow` | `f65_run.sh` | `F587` | `verify587.py` |
| F66 | `differ588` | `cap`, `split` | `f66_run.sh` | `F588` | `verify588.py` |
| F67 | `differ589` | `cond`, `dflt` | `f67_run.sh` | `F589` | `verify589.py` |
| F68 | `differ590` | `cap4`, `cond4` | `f68_run.sh` | `F590` | `verify590.py` |
| F69 | `differ591` | `cap`, `price` | `f69_run.sh` | `F591` | `verify591.py` |
| F70 | `differ592` | `cond` | `f70_run.sh` | `F592` | `verify592.py` |
| F71 | `differ593` | `gro` | `f71_run.sh` | `F593` | `verify593.py` |
| F72 | `differ594` | `cl`, `zc` | `f72_run.sh` | `F594` | `verify594.py` |
| F73 | `differ595` | `all`, `chg`, `cln`, `spl` | `f73_run.sh` | `F595` | `verify595.py` |
| F74 | `differ596` | `all`, `h`, `q` | `f74_run.sh` | `F596` | `verify596.py` |

## 7. Reading a finding against a run

Each finding opens with six labelled fields.  **Run** names the runner and the
log marker; to reproduce one number, boot the instrument with the mode named in
the index, grep its marker, and compare the field to the finding's **Actual**
line and to the tables under **Details**.  A mode can be narrowed with
`mode:limit` (`make_initramfs596.sh` passes the argument through; the
instrument reads the part after the colon as a limit on the number of arms),
which shortens a run.

## 8. What is not in this bundle

* The kernel source tree: use upstream 7.3.4 plus `code/kernel/config-7.3.4-T563`.
* The raw logs of every run: the numbers they contain are in the two documents,
  and the verifiers that recomputed them are in `code/tools/`.
* The working notes of the investigation: every measurement that survived its
  checks is in the two documents, and nothing else is.
