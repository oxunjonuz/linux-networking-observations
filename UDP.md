# UDP aggregation, segmentation and receive memory

| Research records | Subject | Observation |
| --- | --- | --- |
| F62 | Segmentation on forwarding | The study followed a UDP GSO datagram to two exit devices and identified where segmentation occurred on each path. |
| F63–F64 | Headers on an aggregate | After GRO combined datagrams, a rule could see a header describing the aggregate. Interpreting that header as a single original datagram gave a different picture of the traffic. |
| F65–F66 | End of aggregation | The experiments distinguished the limits that ended an aggregate from the memory budget of the socket receiving it. |
| F67–F69 | Memory charged to an aggregate | The measurements followed the charge on the head of an aggregate and compared how it reached the receiving queue across the tested paths. |
| F70–F72 | Changes in packet storage | The tests examined when packet storage could be condensed and how the presence of a user page affected two GRO paths. |
| F73–F74 | Sender alignment and queue capacity | A difference in the sender’s page alignment produced a one-page difference in the charge recorded at the receiver. |

## Receive-queue capacity

F73 and F74 used an IPv4 forwarding path across three network namespaces on one host, running kernel build `7.3.4-T563`. F74 offered 64 identical 512-byte UDP datagrams in each trial. The table gives the effective kernel receive-memory limit and the number queued before the application read them.

| Receive-memory limit (bytes) | Datagrams queued at 5,056 bytes each | Datagrams queued at 9,152 bytes each |
| ---: | ---: | ---: |
| 38,400 | 7 | 4 |
| 51,200 | 10 | 5 |
| 76,800 | 15 | 8 |
| 102,400 | 20 | 11 |

In F73, when the send buffer fit within one page, the recorded charge was 5,056 bytes. When the same payload crossed a page boundary, the charge rose by 4,096 bytes to 9,152. The difference was visible before transmission and persisted through forwarding. At the 38,400-byte limit, the queued datagrams accounted for 35,392 and 36,608 bytes respectively. Those totals matched the recorded receive memory.

The source reports repeated measurements across two boots. The queue counts above apply to uniform charges within each trial. F74 also recorded mixed-charge sequences in which a smaller datagram could still fit after a larger one was refused. A physical network interface and a receiver on a separate machine were outside the scope of these experiments.
