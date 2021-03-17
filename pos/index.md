# 共识机制概念梳理


# 共识机制概念梳理

区块链系统作为一个分布式系统，受限于网络延迟和停电断电等极端情况，为了维持一个一致的系统，首先要解决一致性问题。与此同时，区块链系统又具有去中心化的特征，各个节点相对独立，没有中心节点对于其他节点的恶意行为进行约束。在这样的背景下，需要设立一套制度，使得众多节点能够有序的改变系统的状态，同时使得系统的一致性的以保证。

## 共识

共识，关注的是多个提议者达成一致的过程，共识算法本质上解决的是如何在分布式系统下保证所有节点共同认可某个结果，其中需要考虑节点宕机，网络时延，网络分区等各种问题。

### CAP定理

理想化的场景下，整个系统中所有节点的数据都是相同的，可以任何节点读取或写入数据，产生的效果相同（一致性）；即使某些节点出现故障，系统依然能够正确响应用户请求（可用性）；即使两个节点发生分区，或者说通信中断，集群依然可以继续运行（分区容限）。而由Eric Brewer提出，Lynch等人证明的CAP定理明确了这三种性质不可兼得。所有可用的组合包括：

- **CA**：所有节点之间的数据都是一致的，只要所有节点都处于联机状态，就可以从任何节点进行读/写操作，并确保数据相同，但是如果节点之间发生分区，则数据将是不同步（解决分区后将不会重新同步）。

- **CP**：所有节点之间的数据都是一致的，并且当节点发生故障时变得不可用，从而保持分区容限（防止数据失步）。

- **AP**：节点即使无法彼此通信也将保持联机状态，并且在解析分区后将重新同步数据，但是不能保证所有节点（在分区期间或分区之后）都具有相同的数据

同时满足一致性，可用性和分区容限的系统是并不存在的。假设存在三个节点$$\{A, B, C\}$$用于维护同一份数据，处于某种原因，$$C$$和$$\{A, B\}$$当一个写请求到达$$C$$并要求更新其状态时，$$C$$存在两种选择：

- 即使知道A和B无法同步更新数据仍然接收该请求。
- 拒绝请求，等待与A，B恢复通信后提供服务。

选择前者，即选择可用性而放弃了一致性；选择后者，即选择一致性而放弃了可用性，两者不可兼得。实际上在大规模的分布式应用当中，网络不可靠几乎不可避免，即分区容限是必须的选择，因此**C**和**A**不可兼得，系统设计者必须在**AP**和**CP**之间权衡[[1]](https://codahale.com/you-cant-sacrifice-partition-tolerance/#errata10221010)。

对于CAP定理的使用的解释和应用，应当落脚于当出现问题时，在三种性质中在哪一方面做出妥协：不保证线性一致性、不保证完全的可用性、或者对于网络状况做提出更高的要求，而不是在三者之中选择提供哪两者。

由于CAP中对C和A的定义过度理想化，有人提出了BASE理论，只要求基本可用（Basically Available）、软状态（Soft State）、最终一致性（Eventual Consistency）。核心思想在于即使无法做到强一致性，仍可以根据业务特性，使用适当的方式使得系统达到最终一致性。许多分布式系统都是基于“基本可用”和“最终一致性”来构建的。关于一致性模型的讨论，在这篇文章[[2]](https://wudaijun.com/2018/09/distributed-consistency/)中有更深入的讨论。

总而言之，在共识机制的设计中，也涉及到一系列的妥协，追求的是在各个目标之间找到某种平衡。

## 共识机制

即达成共识的机制，依据系统对故障组件的容错能力分为崩溃容错协议(crash fault tolerant,CFT)和拜占庭容错协议（Byzantine fault tolerant,BFT)[[3]](https://zh.wikipedia.org/wiki/%E5%85%B1%E8%AD%98%E6%A9%9F%E5%88%B6)。

在崩溃容错协议中，如果组件出现故障，系统仍能够正确的达成共识。拜占庭容错协议中，即使存在恶意节点，系统仍能够正确工作。二者的区别主要在于对于威胁/错误模型的不同假设。[[4]](https://stackoverflow.com/questions/56336229/byzantine-fault-tolerance-bft-and-crash-fault-tolerance-cft)

> CFT can withstand up to N/2 system failures, while no guarantees on adversary nodes. BFT provides with guarantees to withstand and correctly reach consensus in presence of N/3 failures of any kind including Byzantine. You can think of it as two phase commit versus three phase commit.

PoW的机制在wiki[[5]](https://zh.wikipedia.org/wiki/%E5%B7%A5%E4%BD%9C%E9%87%8F%E8%AD%89%E6%98%8E)中有清晰的描述。

PoS的思想在这篇博客中[[6]](https://medium.com/@VitalikButerin/a-proof-of-stake-design-philosophy-506585978d51)有深入的思考。核心思想在于在PoW机制中，攻击者和防御者的代价可能是一比一的，对于一个攻击者的51%攻击，需要整个社区几乎相等的算力以挽回其代价，而PoS中，攻击者作恶的代价远高于防御者，与此同时，攻击者的攻击行为带来的收益相对较小。当一个攻击者的攻击行为被发现之后，社区只需要对链做一次分叉，则攻击者的投入以及其收益即全部报销，而对于其他人以及整个系统而言，并没有带来显著的影响，主要思想是通过经济学原理限制作恶。



## 参考资料

[[1]You Can’t Sacrifice Partition Tolerance](https://codahale.com/you-cant-sacrifice-partition-tolerance/#errata10221010)

[[2]一致性杂谈](https://wudaijun.com/2018/09/distributed-consistency/)

[[3]Wikipedia 共识机制](https://zh.wikipedia.org/wiki/%E5%85%B1%E8%AD%98%E6%A9%9F%E5%88%B6)

[[4]Byzantine fault tolerance (BFT) and Crash fault tolerance (CFT)](https://stackoverflow.com/questions/56336229/byzantine-fault-tolerance-bft-and-crash-fault-tolerance-cft)

[[5]Wikipedia 工作量证明](https://zh.wikipedia.org/wiki/%E5%B7%A5%E4%BD%9C%E9%87%8F%E8%AD%89%E6%98%8E)

[[6]A proof of stake design philosophy](https://medium.com/@VitalikButerin/a-proof-of-stake-design-philosophy-506585978d51)
