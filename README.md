# Linux networking observations: nftables and UDP GRO/GSO

A UDP socket with a receive-memory limit of 38,400 bytes queued seven identical 512-byte datagrams in one trial and four in another. Both endpoints ran on the same host. The difference tracked the alignment of the sender’s zero-copy buffer and the memory charge that reached the receiving socket. [Measurement table and scope](UDP.md#receive-queue-capacity)

This collection summarizes 45 observations recorded by Oxunjon Ubaydullayev’s research agent. The identifiers follow the original research log. F34 does not designate a separate observation.

| Report | Records | Question |
| --- | ---: | --- |
| [nftables payload handling](NFTABLES.md) | 32 | How do packet representation and the point at which a rule runs affect what it can observe? |
| [UDP aggregation, segmentation and receive memory](UDP.md) | 13 | What happens to a datagram’s headers and memory charge as it passes through the networking stack? |
| [Verification and limits](VERIFICATION.md) | | Which checks did the original bundle pass, and which measurements still need independent confirmation? |

The reports describe experiments on identified kernel builds. Some observations document expected behaviour. The records do not establish 45 bugs. Maintainers interested in a particular measurement can request its test sources, configuration and evidence from the author by finding ID.
