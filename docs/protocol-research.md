# 协议性能研究：先得到可比较的数据

研究基线：2026-11-27。本文区分代码事实、标准事实、待验证假设和本地测试结果。
本次增加受控比较工具，不改变生产协议、订阅字段、拥塞控制默认值或智能线路策略。

## 1. 目标与物理边界

目标是找到不同网络条件下的较好取舍：有效吞吐量、带负载的响应时延、连接成功率、故障恢复时间、
CPU/内存/电量、实际传输字节和隐私。单个峰值下载数字不能代表这些目标。
拥塞控制需要同时考虑队列、丢包和其他流的公平性；新的算法也应接受这种评价，见
[RFC 9743，尤其第 5–7 节](https://www.rfc-editor.org/rfc/rfc9743.html)。

以下是研究中的推导，不是本项目已有的实测结论：

- 单台 VPS 的出口、客户端接入带宽、链路 RTT、CPU 或网卡都可能成为瓶颈。同一条瓶颈链路上并行使用两个协议，
  不会凭空产生两倍可用容量。多开流获得的更大份额还需要与其他用户的公平性一起评价。
- 带宽时延积 `BDP = bandwidth × RTT` 决定了维持目标速率需要多少在途数据。例如 100 Mbit/s、100 ms 的 BDP
  约为 1.25 MB；这只是数量级估算，不是接收窗口的通用推荐值。内存上限、双向流量和并发连接同样重要。
- 吞吐量高而队列很长，网页、语音和游戏仍可能变慢。需要一起记录吞吐量与带负载的时延。
- 协议加密保护内容，并不自动隐藏通信双方地址、时序、包长和总流量。填充、冗余和多路径可能改善某些目标，
  也会增加带宽、电量、状态和可关联的信息；不能宣称“绝对隐私”或“全方面最优”。

## 2. 当前实现是什么

源码基线分别为服务端 `4192530d133722000a84d6cc9e8371941489b6da`、客户端
`33f3dfbd84d3a0d8c7ceb43d64016fb3f56ac122`。版本名和同名配置项不等于同一实现。

| 组件 | 当前版本或源码位置 | 能确认的行为 / 研究边界 |
| --- | --- | --- |
| Xray 服务端 | `install.sh:16`，`v26.3.27` | 现有 TCP/REALITY 候选。安装脚本明确保留此版本以兼容客户端；本文不升级它。 |
| Hysteria 服务端 | `install.sh:17`，`app/v2.14.0` | [该 tag 的 core/go.mod](https://github.com/HyNetworks/hysteria/blob/app/v2.14.0/core/go.mod) 使用 `apernet/quic-go v0.65.1-0.20261109005002-2895f039137a`。 |
| Hysteria 配置 | `vps2vpn/cores.py:145–187` | 按内存分档设置 QUIC 窗口，保留 PMTU 发现，`ignoreClientBandwidth=true`；不接受任意客户端目标速率作为默认发送速率。 |
| Hysteria 迁移 | [v2.14.0 server.go](https://github.com/HyNetworks/hysteria/blob/app/v2.14.0/core/server/server.go) | 设置 `DisablePathManager=true`。不能把通用 quic-go 的迁移文档直接当作此部署已启用的行为。 |
| TUIC 服务端 | `install.sh:18`、`vps2vpn/cores.py:190–213`，sing-box `v1.14.4` | TUIC v5、`congestion_control=bbr`，`zero_rtt_handshake=false`。该字符串不足以证明算法是 BBRv3。 |
| 客户端 Mihomo | `core/Clash.Meta` gitlink `5b453f80dbcee6b3ecfb0415bcace24a48c88707` | [固定版本的 TUIC 拥塞控制分派](https://github.com/chen08209/Clash.Meta/blob/5b453f80dbcee6b3ecfb0415bcace24a48c88707/transport/tuic/common/congestion.go) 把 `bbr` 和 `bbr_meta_v2` 映射到 `congestion_v2.NewBbrSender`；目录名不代表 IETF BBRv2 或 BBRv3。HY2 也调用这一分派。 |
| 客户端 QUIC 依赖 | `core/go.mod` | `metacubex/quic-go v0.61.1-0.20260727080200-2548683b76f4`、`metacubex/sing-quic ...1c242664697a`；与服务端不是同一 fork/版本。 |
| 客户端 TUIC 握手 | [固定版本 adapter/outbound/tuic.go](https://github.com/chen08209/Clash.Meta/blob/5b453f80dbcee6b3ecfb0415bcace24a48c88707/adapter/outbound/tuic.go) | `reduce-rtt` 会进入 `DialEarly`；服务端是否接受 TLS early data 仍由服务端决定。必须分开测试完整握手、恢复、early-data 被拒绝及重试。 |
| 系统拥塞与队列 | `vps2vpn/system.py:48–116`、`vps2vpn/shaper.py` | TCP 使用 `bbr`/`fq`，限速类使用 `fq_codel`。TCP sysctl 不会替换用户态 QUIC 的拥塞控制器。不得用全局 `tc` 操作覆盖已有队列所有权。 |
| 智能线路 | 客户端 `core/vps2vpn_smart.go:617–690,766–858` | 同服务器协议组采用优先级 fallback，多服务器使用 url-test。现有 HTTP 探测、容差和故障阈值不是带负载时延或吞吐量优化器。 |

最新版官方配置文档把 Hysteria 的非 Brutal 默认控制器标为 **BBR v1**，另有 Reno 与 BBR profile；
这些选项属于端点本地设置，不是新协议协商字段。见
[Hysteria 完整配置说明](https://www.hy2.io/docs/advanced/Full-Client-Config/)。
修改任何参数前仍须检查上述固定版本的解析器和实现，不能仅凭最新文档给旧客户端下发配置。

## 3. 标准与机制的最新状态

| 技术 | 截至研究日期的事实 | 对项目的含义 |
| --- | --- | --- |
| QUIC v1 | [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html) 定义独立流、流控和连接迁移；[RFC 9002](https://www.rfc-editor.org/rfc/rfc9002.html) 定义丢包恢复、PTO 和拥塞控制。 | 独立流可减少跨流的传输层队头阻塞；同一流仍按序交付，连接仍受共享拥塞/流控资源影响。不能承诺“无队头阻塞”。 |
| QUIC DATAGRAM | [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html) 提供不可靠数据报，仍受连接拥塞控制约束，不做传输层重传。 | 适合保留原生 UDP 的时效性；过期包应丢弃而不是无限积压。它不保证应用已处理数据，也不增加链路容量。 |
| HTTP Datagrams / MASQUE | [RFC 9297](https://www.rfc-editor.org/rfc/rfc9297.html)、[CONNECT-UDP RFC 9298](https://www.rfc-editor.org/rfc/rfc9298.html)、[CONNECT-IP RFC 9484](https://www.rfc-editor.org/rfc/rfc9484.html)。 | 可作为以后互通实验的候选。HTTP/2/1.1 Capsule 回退是可靠传输，不能假装仍具有 QUIC DATAGRAM 的丢包/时延性质；CONNECT-IP 还涉及路由、MTU 和权限。 |
| Multipath QUIC | [RFC 10069](https://datatracker.ietf.org/doc/html/rfc10069) 已于 **2026 年 11 月**成为 Proposed Standard；它不定义应用的最优调度器。 | 标准存在不等于当前依赖已支持/启用。真实多接入可研究冗余或聚合，但需处理共享瓶颈公平性、重排、每路径状态及能耗；同流跨高低延迟路径可能等待慢路径。 |
| BBRv3 | [draft-ietf-ccwg-bbr-07](https://datatracker.ietf.org/doc/draft-ietf-ccwg-bbr/) 于 **2026-11-02**更新，目标状态为 Experimental，仍是草案。 | 可在隔离实验中与当前算法对照；不能把项目现有 `bbr` 字符串称为 BBRv3，或默认切换生产内核。 |
| L4S | [RFC 9330](https://www.rfc-editor.org/rfc/rfc9330.html) 与 [RFC 9332](https://www.rfc-editor.org/rfc/rfc9332.html) 描述端点和瓶颈 AQM/ECN 的配合。 | 仅改 VPS 参数并不能保证路径获得 L4S 效果。需要确认发送端、反馈和瓶颈队列支持，并验证与传统流共存。 |
| FQ-CoDel | [RFC 8290](https://www.rfc-editor.org/rfc/rfc8290.html) 是 Experimental，结合流队列与 AQM，降低排队干扰。 | 可在自己控制的瓶颈处实验；一个加密隧道封装多流后可能被外层队列视为一个流。已有 HTB/fq_codel 不能被研究工具悄悄替换。 |

### MTU、握手和隐私是约束，不是可随意取消的开销

QUIC 要求路径支持至少 1200 字节的 **UDP 负载**，这不是 TUN MTU；IP、UDP、QUIC 和隧道封装均占空间。
见 [RFC 9000 第 14 节](https://www.rfc-editor.org/rfc/rfc9000.html#section-14)。应分别测试 IPv4/IPv6、
较小 MTU、ICMP 黑洞和 PMTU 变化，保留发现机制，避免为了吞吐量盲目增大发包大小。

0-RTT 会带来重放风险；应用协议必须规定安全使用条件。
[RFC 9001 第 5.6、9.1–9.2 节](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.6)
也讨论会话票据的关联性。不能为了少一次往返对管理操作、付费动作或其他非幂等请求默认启用 early data。
TLS 验证、证书身份和升级签名不作为性能实验的可关闭变量。

[Hysteria 协议规范](https://v2.hysteria.network/docs/developers/Protocol/) 使用 QUIC 流承载 TCP、数据报承载 UDP，
并通过认证响应协商速率模式；其 UDP 分片缺失时整包不能交付。
[TUIC v5 规范](https://github.com/tuic-protocol/tuic/blob/master/SPEC.md) 区分 native 数据报和 stream UDP relay。
研究中需要区分这些语义。协议的伪装目标也不是对所有观察者不可区分的证明；流量分析仍需单独威胁模型。

## 4. 本次交付：可复现的受控比较入口

原来 `tools/bench.py` 按固定顺序先测 direct，再逐条测代理；默认公共测速源会分别探测和回退。
当路径 A 走一个下载站、路径 B 走另一个站，或者 1 路和 4 路下载切换了来源时，旧 JSON 不能解释差别。
这些数据可用于排障，不能直接给协议排名。

现在默认测速保留原数值字段和回退行为，**额外**记录来源策略、下载来源 ID 和每次实际下载尝试。
`attempts` 是完整测速尝试，不包含短暂的来源可用性预探测。失败尝试不会因后续来源成功而消失。
默认模式的 JSON 顶层仍为 `time` / `results`；结果内新增诊断字段，因而不是字节级不变。

显式 `--origin` 不回退，并拒绝所有 HTTP 重定向；若 fixture 返回 3xx，就记录失败。
受控 fixture 应在 `/generate_204` 返回 204，`/__down?bytes=N` 返回测量数据，`/__up` 接收 POST。
使用同一请求 origin 是必要条件；研究者还须保证它指向受控的相同后端，而不是按来源分流的 CDN。

```bash
python tools/bench.py --config synthetic-config.json --mihomo /path/to/mihomo \
  --origin http://127.0.0.1:18080 --compare --quick \
  --rounds 4 --seed 7 --budget 600 --sample-timeout 120 --json comparison.json
```

这个命令只示范参数。`127.0.0.1` 是 **发起 HTTP 请求的一端**的回环地址；有远端代理时通常指向 VPS，
不是运行工具的电脑。跨代理比较须使用自己明确控制、各路径都能到达的同一个 fixture，
例如 `https://benchmark.example.com`；此处域名只是占位符，工具不会为用户部署或发现测试站。

比较模式具有以下边界：

- 默认 3 轮、seed 0；第一次将路径洗牌，以后每轮轮转。一个完整的位置平衡周期需要至少“路径数量”轮，
  并应选择完整周期的整数倍。少于一个周期的结果仍保留真实顺序，不能宣称位置完全平衡。
  由于轮数上限为 20，超过 20 条路径时无法在一次运行中完成完整周期；需要减少路径或分组实验，
  并在报告中保留分组信息，不能把分组结果当作同一次完整平衡实验。
- 最多 32 条路径（包括 direct）、20 轮，一次只测一个样本；样本内部沿用 1/4 条下载连接。
- 默认采样总预算 600 秒、单样本 120 秒，上限分别为 3600 和 300 秒。预算覆盖采样进程启动与采样；
  超时回收进程最多另需约 2.1 秒，OS 调度可能增加延迟。核心就绪等待单独限为总计 15 秒。
  配置读取/订阅获取、核心启动和最终文件写入不在采样预算内；它不是整个 CLI 的硬实时保证。
- 超时只终止本次 HTTP 采样子进程。Mihomo 由父进程持有，并由已有 `finally` 负责关闭；
  采样子进程不启动孙进程。工具不更改系统代理、TUN、路由、sysctl 或队列。
- 版本化输出 `vps2vpn.protocol-comparison.v1` 包含 `method`、匿名 `paths`、逐个 `samples`、
  计划数/实际数/成功数、完成状态。每个有测量结果的样本仍包含原 `latency/down_1/down_4/up_1` 字段。
  不生成“最好的一次”排名，不剔除失败；不完整结果退出码为 1。
- 路径用 `p01` 等匿名编号和有限协议类型表示；JSON/进度日志不输出订阅、节点名、origin 主机或 query。
  含凭据、路径、query、fragment 的 origin 在采样前拒绝。公开报告仍须检查其他手工补充的环境记录。

此工具仍只测 **新建 HTTP(S) 请求耗时**、串行下载/上传阶段。它不是 ICMP RTT，不测带负载时延，
也不等于新建外层代理握手；同一 Mihomo 在各样本间存活，HY2/TUIC 可能复用外层连接。
5/10 次请求的 `p90` 是排障摘要，不足以推断稳定的 p99。冷/热外层连接必须在进一步实验中分开控制。

## 5. 下一步研究：在现有协议上做自适应选择

**待验证假设：**以相同服务器的现有 TCP/HY2/TUIC 为候选，在网络状态改变时更新选择，
可能改善 UDP 被限速、弱网或休眠恢复时的用户体验；不需要先发明新密码算法或替换 wire protocol。
此假设尚未做 Windows/Android/VPS 端到端测量，不能据此更改默认排序。

建议先做只记录建议、不实际切换的 shadow 模式；审核数据后，再讨论用户主动开启的新连接选路模式：

1. 将探测归入本地网络状态周期：上线、地址变化、休眠唤醒、持续失败触发新周期，旧测量适时失效。
2. 同服务器候选使用一致的小型健康探测，设速率/字节/并发上限；不在后台周期性跑全速测速。
   区分 UDP 不通、目标站错误、DNS/TLS 错误、整个网络离线，避免一次超时触发全局来回切换。
3. 用重复证据、滞后阈值和最短保持时间抑制抖动；显式用户选择优先。阈值在实验前登记，不能事后挑成绩。
4. 只给新连接选路；现有 TCP/QUIC 流不应被称作可跨不同协议无损迁移。AI/登录等要求出口稳定的流保持粘性，
   同时保留可解释的故障恢复规则。
5. 第三方订阅保留原节点类型和显式策略；没有可验证的同服务器关系时不自动合并。不能仅凭节点名称猜测。
6. 只保存本地匿名计数和分布，不上传真实节点、IP、域名、DNS 请求或订阅；关闭功能即可回到既有策略。

若以后研究 MASQUE、RFC 10069 多路径或新的隧道语义，需要独立的版本/能力协商、旧协议回退、
安全评审、互通矩阵和资源上限。此类协议/API 变更应先开 Issue 讨论，不能附带在测速修复中部署。

## 6. 可重复实验矩阵与接受门槛

以下是**实验设计**，不是已经测过的数据。先用筛选矩阵找到问题区域，再对关键区域增加重复次数；
不必把所有维度做成本极高的全笛卡尔积。

| 维度 | 建议覆盖 | 需要解释的机制 |
| --- | --- | --- |
| 带宽与 RTT | 双向 10/50/100 Mbit/s，非对称上/下行；RTT 10/80/200 ms | BDP、上行 ACK/队列、CPU 上限 |
| 丢包与抖动 | 0/0.1/1/3% 随机丢包，再加突发丢包、重排和时延变化 | 重传/PTO、误判拥塞、数据报截止时间 |
| 队列 | 浅/深队列，上传、下载及同时双向负载；与一条传统 TCP 流竞争 | bufferbloat、公平性、短流尾延迟 |
| UDP 可用性 | 全阻断、间歇阻断、限速、NAT 映射失效 | 必须有已验证的 TCP 候选及恢复规则 |
| MTU | IPv4/IPv6；1280/1500 字节 IP MTU，另测无法承载 1200 字节 UDP 负载的失败路径 | 封装开销、PMTU 黑洞、不能混淆 IP MTU 与 UDP 负载 |
| 资源 | 1 vCPU/512 MiB 与 2 vCPU/2 GiB 等代表性 VPS；弱/强客户端 | CPU 秒/GiB、RSS、线程/句柄、空闲开销、电量 |
| 生命周期 | 冷/热外层连接、睡眠唤醒、Wi-Fi/蜂窝切换、IPv4/IPv6 切换、核心重启 | 真正恢复时长、已有连接损失、代理状态恢复 |
| 兼容 | 现有服务端/客户端，旧版本，第三方订阅；Windows 系统代理/TUN、Android VPN | 不因新选择策略破坏已有连接和用户明确选择 |

每组实验固定 fixture 后端/证书、数据大小、内核二进制 SHA-256、配置版本、系统/驱动版本和测量顺序。
环境记录只发布匿名硬件等级与合成配置；证书私钥、真实地址和原始订阅不入库。
同一个配对样本中只改变一个待比较因素；交错不同协议的运行，保留所有错误、超时、预算未执行的样本和异常原因。

建议报告：有效字节吞吐量、独立小请求的空闲/带负载 p50/p95/p99、失败率、恢复时间、CPU 秒/GiB、
RSS/句柄/空闲唤醒、线上字节/有效字节。少量样本不能给可靠的尾部分位数；正式比较须根据方差与效应大小
预先确定样本量，报告区间估计，区分无数据、失败与低吞吐量。

作为需要讨论的初始接受门槛，可要求弱网场景带负载 p95 有稳定改善，同时吞吐量、失败率、资源和公平性
不突破事前设定的容忍区间；不同用途允许选择不同目标权重。不能因为一个测试点快 5% 就宣称普遍更快。
任何路径上的 TLS/鉴权降级、资源无界增长、错误覆盖或已有连接被意外切断，都应阻止默认启用。

## 7. 本地证据与未验证项

`tests/test_benchmark_comparison.py` 使用两类证据：

- 确定性 mock：证明旧结果遗漏来源/失败尝试、轮转与预算逻辑、匿名输出及参数验证；不算协议性能实测。
- 真正 loopback HTTP：执行请求、下载/上传、拒绝重定向；实际 spawn 进程返回失败样本，以及阻塞请求超时后
  采样进程被回收。缩短的数据大小和时间只用于测试。没有启动 HY2/TUIC/Xray，也没有远端性能结论。

本次没有配置宿主 `tc`、系统代理或 TUN，没有访问真实订阅/测速 VPS，没有完成 Windows/Android 网络栈、
真实丢包链路、L4S、BBRv3 或 RFC 10069 互通实验。上述矩阵需要在独立测试设备/命名空间中执行，
先确认资源与拓扑，再发布可审计的实测结果。
