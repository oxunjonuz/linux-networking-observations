# nftables payload handling

The 32 records cover several representations of the same network traffic. A VLAN tag, for example, may be visible in the bytes of an Ethernet frame or carried separately in kernel packet metadata. An observation at a rule therefore needs a location in the packet path as well as a protocol name.

| Research records | Subject | What the measurements show |
| --- | --- | --- |
| F29–F33 | Encapsulation and protocol fields | Outcomes differed across header bases and protocol families. Some syntactically accepted assignments left the measured field unchanged. |
| F35–F39 | Ethernet headers and VLAN tags | The visible link header depended on the device and the representation of a tag. The trials included single and stacked tags. |
| F40–F44 | Header coordinates | Reads and writes agreed in some tested paths and diverged in others. The comparisons included PPPoE and multiple ways the kernel constructs packet metadata. |
| F45–F50 | IPv6, forwarding devices and header availability | Locating a transport header could involve walking the IPv6 header chain. Some tested devices exposed no Ethernet header at the observation point. |
| F51–F56 | Packet copies and VLAN processing | The measurements traced what survived between packet copies, which representation a rule saw, and which tag the egress device emitted. |
| F57–F59 | Privilege and rule context | The study distinguished the privileges used to install a rule from the behaviour seen when traffic later traversed it. Results also varied with the rule context. |
| F60–F61 | UDP checksum processing | On the measured partial-checksum path, the value visible during forwarding represented an intermediate stage of checksum calculation. |

## Scope

The rules in these experiments were installed by root in the initial user namespace. The measurements describe outcomes for those rules and packet paths. They do not demonstrate privilege escalation or memory corruption. The source report labels possible defects as observations pending maintainer review.
