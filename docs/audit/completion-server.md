# 服务端审计补充：状态、权限、调度和跨仓库兼容

日期：2026-11-20。对应 [服务端 PR #1](https://github.com/xydadada/vps2vpn/pull/1)，关联 [客户端 PR #2](https://github.com/xydadada/vps2vpn-client/pull/2)。

本次补充以服务端 PR 原头 `fbe37818e5b56c23f0af2b1e9ddf9bb82d9f9bbe` 为起点，同时纳入默认分支 `65425087c628585379cdc17f3919f4ff17a32fad` 的 0.2.1 更新。保留新版逐服务器线路报告、HTTP 会员 API 的 426 提示和既有兼容行为。先前审计基线为 `a30d4eb6cc87c2d73b4e25b4c1acf23201537a48`；之前已提交的发现、代码阅读清单和对应 CI 证据继续保存在 [总报告](2026-11-20.md)、[后端报告](backend.md) 和 [覆盖台账](coverage.tsv)。旧提交的绿灯不代表本次新增修改已经通过。

## 审查方法和实际范围

先对照远程 PR、更新后的默认分支与本地未提交补丁的固定快照，避免把另一项进行中任务的变化直接当成本次修复。逐项检查这些补丁的根因、依赖和测试，再沿真实调用路径续审：请求解析→身份验证→会话发布；邀请码→预算预留→后代消费→停用/删除；统计采样→月重置→限额→核心应用；签发身份→证书选择→订阅 SNI/pin→真实 TLS；Telegram 长轮询→权限重查→命令/备份；Xray 嗅探→DNS 解析→路由→实际出口。

这是一份在前次完整阅读台账之上的续审报告，不把本轮差异复核冒充第三方核心全文审计，也不把文件阅读数等同测试覆盖率。对 Xray 只读取了与确认问题直接相关的固定版本源码。新增用例复用真实 SQLite、回环 HTTP/TLS 和实际核心配置校验；在故障、竞态和外部服务边界使用受控替身。

## 本次确认问题、修复与证据

下表以文件及函数定位，最终变更行号可在 PR 的 Files changed 中查看。严重度表示本项目实际影响，所需权限与触发条件同时列明。

| ID | 严重度 | 文件 / 函数 | 根因和影响 | 实际修复 / 主要回归 |
| --- | --- | --- | --- | --- |
| S01 | 高 | `web.py:rate_limited/auth_succeeded` | 任意会员的一次成功登录会清空同 IP 的全部失败预算，会员可边成功登录边猜测其他身份；并发请求和 keep-alive 还会混淆预算归属。 | 每次认证持有独立预留对象，成功只释放自己的预留；使用单调时钟。`test_audit.WebAudit` 覆盖跨身份、同一时钟 tick、过期预留和同连接重复登录。 |
| S02 | 高 | `web.py:api_login/api_password/member_area/api_user_action` | 哈希验证在事务外完成，管理员重置密码、改名、启用第二因素或删除会员后，早先通过验证的请求仍可能签发新会话；改密码与撤会话分开提交也可留下半次结果。 | 验证后在会话发布事务内重读身份/密码/第二因素；变更与撤销、签发共同提交。并发密码修改不能覆盖已更新的 hash。`test_completion_server.CredentialPublication` 覆盖密码/用户名/TOTP 变化、删除及签发故障回滚。 |
| S03 | 中 | `web.py:Handler.setup/handle_one_request/_RequestReader` | 单次 socket 空闲超时可被持续小字节发送不断续期，使预算内工作线程长期占用。 | 每个请求的请求行、头和正文共用 20 秒读取截止点，每次底层读取使用剩余时间；保留线程上限。这不是业务处理、写响应或全链路总超时。 |
| S04 | 中 | `web.py:route/_read_body/_read_chunked/body_json` | 路由前缺少统一 framing 检查，已缓存正文再以更小限制解析时未复查；恢复/同步需要的大小限制不一致；损坏 JSON、超长数字和截断处理不完整。 | 路由前有界读取；一般 4 MiB、已认证恢复 32 MiB、已认证同步 8 MiB；对象/有限数字/格式错误受控返回 400 并关闭连接。保留合法 chunk 扩展和 pipeline 边界测试。 |
| S05 | 中 | `web.py:apply_async` | 每次改动各建一线程后串行等待，突发请求累积线程；强制重载和应用过程中的后续更新可能丢失。 | 单个工作线程合并待应用更新，保留 force 位，应用失败后仍处理期间新到的变更；线程启动失败可重试。`test_apply_audit.ApplyWorker` 的突发、在途失败、启动失败用例。 |
| S06 | 高 | `members.py:reserved/create_invite` | 预算计算复用 `db.invites()` 的最近 100 条展示列表。后来创建/撤销的历史足够多时，仍有效的旧邀请码消失，预留额度及最多 5 个待用码限制被绕过。 | 业务限制改为直接在全部活动记录上 `SUM/COUNT`，展示列表继续分页。`test_completion_server.InviteReservations` 将旧有效码挤出 100 条窗口后检查预算、拒绝超额和兑换。 |
| S07 | 高/中 | `members.py:_subtree_charge/spent_bytes/given_away`、`db.py:delete_user` | 停用或删除受赠账户时返还已消费额度，祖孙链可能重复支出原预算；递归方式受 Python 栈深限制。删除由管理权限触发。 | 只释放真正未用额度，活跃下级保留原承诺额；迭代汇总后代消费；删除时把已消费且不超过原赠额的债务留在邀请者计数中，不重复插入历史流量。`test_audit.SharedQuota` 覆盖消耗/暂停/删除、祖孙、深链和损坏环。历史账期限制见下文。 |
| S08 | 高/中 | `jobs.py:enforce/_quota_order` | 月重置与采样、管理员暂停不共享事务，旧快照可抹去新流量或覆盖暂停；边遍历边重置造成父账户先看到子账户上期消费；用 ID 倒序不能保证恢复后的父子顺序；事务内通知可能在回滚后已发出。 | 所有重置先完成，按实际邀请边自底向上判断，同一 DB 事务提交；通知和日志仅提交后发送。`test_ops_audit.EnforcementConcurrency` 覆盖并发写入、暂停、故障回滚、ID 重排和深图。 |
| S09 | 中 | `db.py:transaction/update_user`、`web.py:api_users_bulk` | SQLite 自动回滚后再次 ROLLBACK 掩盖原异常；改名只在创建路径检查唯一性；批量管理动作中途失败可留下半组变更。 | 只在仍处事务中回滚，保留原异常；事务内检查 NOCASE 重名；批量修改一个事务。`test_audit.Transactions` 及已有管理测试。 |
| S10 | 高 | `cores.py:xray_config` | `routeOnly=true` 并不表示私网检查仍使用实际目的地址。嗅探得到的公共 HTTP Host/TLS SNI 被放进 RouteTarget，IPOnDemand 优先解析它，出口仍连接原来的私网目标。有效代理用户可以构造二者不同的流量。 | 保留协议嗅探、清空 `destOverride`，不让客户端内容改写地址判定。配置回归加真实 E2E 的 CONNECT 私网目标/公共 Host 测试；测试框架自身用确实转发的代理作负控制。固定源码证据见下一节。 |
| S11 | 高/中 | `certs.py:trusted/ensure_self_signed/_issue`、`__main__.py:cert` | SAN 和到期检查不能证明 CA 信任；staging 或放入 ACME 路径的自签证书可能被宣传成受信；证书存在而私钥损坏/不匹配时继续复用；staging 覆盖活动证书。 | 校验系统信任链、用途及证书私钥配对；损坏自签对重新生成；staging 写独立后缀且不激活、不标记生产成功；生产签发强制重载内存中的证书。配置和本地证书测试通过，未请求真实 ACME。 |
| S12 | 中 | `certs.py:current`、`cores.py`、`subscription.py:_tls_info`、`cluster.py:join_code`、`web.py:TLSContext`、`jobs.py`、`__main__.py` | 域名证书和连接地址可以不同。正常设置域名会同时更新地址，但之后仅修改地址或恢复合法的独立字段时，签发、面板、内核与订阅选择了不同身份。 | 一致选择 `domain or public_host` 作为证书身份，内核使用传入设置；连接地址仍可独立。用本地 CA 签 localhost 证书、连接 127.0.0.1，验证订阅 SNI、三处配置/加入码及真实 HTTPS 主机名/链验证。 |
| S13 | 中 | `subscription.py:clash/singbox/shadowrocket` | 全部线路停用/账户停用时，空 selector/urltest 配置无效，Shadowrocket 还可能回退 DIRECT。 | 空配置明确拒绝代理流量，避免静默直连或无效组。`test_audit.SubscriptionIntegrity`；保留当前格式及字段。 |
| S14 | 中 | `notify.py:find_chat/send_file/bot_loop` | 群消息可被选为备份目的地；首次空轮询后第一条真实命令被丢弃；禁用期间旧消息可能在重新启用后执行；长轮询期间撤销权限后仍处理旧结果。 | 备份/命令限定已配置私聊，启动只取尾部并检查时间，空启动不会误丢下一条；禁用/换 token/chat 后在处理前重查。`TelegramSafety` 与 `NotificationOwnership` 用例，无真实消息发送。 |
| S15 | 中 | `notify.py:_call/send` | 并发告警都能通过同一节流检查；`ok:false` 被当成发送成功而消耗冷却期；墙钟变化影响节流，响应无界。 | 锁内预留在途发送，单调时钟冷却，失败释放名额，成功才记入；检查 API 对象/ok 且限制响应。并发发送与失败后重试回归。 |
| S16 | 中 | `monitor.py:probe/speed/has_ipv6/run_in_background` | TLS 读失败泄漏 socket；重复触发监控生成多轮并发任务；测速把 HTTP 错误页也计入字节，不能区分限流和有效载荷。 | 生命周期用上下文管理，HTTP 状态校验、读取字节/时间边界；单轮在途，线程启动失败释放名额。读失败资源和工作线程重试回归。 |
| S17 | 中 | `rules.py:_fetch/refresh/refresh_in_background` | 超过 50 MiB 被截断后仍发布为规则；HTTP 读取错误处理不全；进入新线程后才竞争锁，突发刷新仍创建大量线程。 | 多读一字节并拒绝超限，错误保留旧文件，创建线程前预留执行权并在异常释放。静态检查及故障边界复核。 |
| S18 | 中 | `secure.py:check_password`、`__main__.py:cmd_reset_password` | 非字符串密码及损坏 hash 轮数可抛异常或造成无界工作；恢复数据也能进入该路径。原管理员 Web/CLI 接受长于 128 字符的密码，直接给验证函数加上限会锁死合法旧账户。 | 验证类型及 1–10,000,000 的整数迭代范围，异常按不匹配处理；Web/CLI 新设置和修改统一 8–128 字符，验证既有 hash 不强加这个新写入上限，HTTP 正文已有大小边界。CLI 改密/撤会话同事务；边界、撤销失败及旧长密码真实 HTTPS 登录/迁移回归。 |
| S19 | 中 | `system.py:sysctl_text/port_hopping/CLOUD_HINTS` | tcp_mem 假定 4 KiB 页，在其他页大小上偏离预算；替换 nft 跳端口表先删旧规则，失败后服务中断；云提示建议开放所有端口。 | 读取实际页大小；先校验再一次 nft batch 原子替换；指引仅开放实际列出的端口。页大小和 nft 调用回归。未宣称已经在所有云或 ARM VPS 实测。 |
| S20 | 中 | `install.sh:do_install/restore_previous_app` | 初始化、服务启动、核心配置失败可能仍显示安装成功；部分升级失败没有恢复原面板代码。 | 失败明确非零返回，尝试恢复已有代码及重载；核心应用错误保留诊断。回归检查错误传播；真实升级故障/恢复需隔离 runner 验收。不是数据库/所有系统配置的完整回滚。 |
| S21 | 中 | `bench.py:_failure/download/upload` | 错误字符串可能包含订阅/测量 URL 凭据；上传大小不是块大小整数倍时实际发送长度与宣称不一致；线程 HTTP 异常仅变成无原因的 0。 | 输出有界且去敏感信息的错误类型/状态，保留可行动诊断；尾块按精确剩余长度发送；不降低失败标准。`BenchmarkErrors` 和已有工具回归。 |
| S22 | 中 | `aicheck.py:_claude_web/summary/score` | Claude 网站不可达/未知但 API 返回成功时，汇总误报可用；浏览器挑战被推断成必然可访问。 | 两项都成功才报可用，保留 blocked/unreachable/unknown 状态；挑战保持未知，分值文档改为实际 0–4 范围。专项分类测试。没有改变未经地区实测的网络参数。 |
| S23 | 中 | `static/kit.js:quotaUsage/Theme`、`static/app.js`、`static/member.js` | 有限账户有效额度恰为零被显示为无限，低余额筛选与进度条同样错误；反复挂载累积 UI 事件。 | 以原额度区分有限/无限，以有效额度计算进度；零额度显示耗尽；复用事件处理器、去重监听、异步返回前确认 DOM。Node 回归覆盖零额度、挂载和刷新。 |
| S24 | 中 | `db.py:_check_backup_settings` | 0.2.1 新 `user@host` 线路报告恢复键仍按纯用户 ID 校验，合法新版备份被拒绝。 | 兼容旧纯 ID 与新复合键，同时检查协议、用户 ID、时间、主机值一致性，保留新主分支行为。既有新版线路/备份测试。 |
| S25 | 中 | `web.py:member_area/report`、`jobs.py:report_line`、`db.py:_check_backup_settings` | API 把任意 JSON 值强制转 bool，字符串 `"false"` 被当成恢复成功；host 允许控制字符写入，但备份恢复拒绝同一记录，普通会员即可制造不能恢复的导出备份。 | 保留线上 `{line, ok, host}` 格式，要求有效协议、真实布尔值和不含控制字符的字符串主机；写入与恢复边界一致。真实 HTTPS 回归检查 18 种损坏输入无状态变化，以及域名规范化/IPv6 多主机导出恢复、逐主机恢复。 |

## 两项需要追到数据流的根因

### Xray 的 routeOnly 不是目的地址完整性保证

固定版本 v26.3.27 的 [dispatcher/default.go](https://github.com/XTLS/Xray-core/blob/v26.3.27/app/dispatcher/default.go) 在命中嗅探覆盖条件后把嗅探域名赋给 `RouteTarget`，实际出站 `Target` 可以仍是原地址。[routing/session/context.go](https://github.com/XTLS/Xray-core/blob/v26.3.27/features/routing/session/context.go) 让路由的域名读取优先使用 RouteTarget；[routing/dns/context.go](https://github.com/XTLS/Xray-core/blob/v26.3.27/features/routing/dns/context.go) 的 `GetTargetIPs` 又先解析这个域名，再考虑实际 IP。因而只设置 `IPOnDemand` 或 `routeOnly` 都不能独立修复此组合。

本项目服务端的私网阻断应基于用户真正请求连接的地址；保留协议识别供 BitTorrent 规则使用，移除对 Host/SNI 的地址覆盖。客户端本地分流生成逻辑没有因此被移除。E2E 新增 12 个伪装 Host 用例，与已有的 12 个直接私网拒绝用例分别验证；只有公网正控制成功后才执行，避免把死客户端误认为成功阻断。

另在当前容器用实际 Xray v26.3.27 做了四个修复前/后的受控验证：保留生产生成器的路由和嗅探设置，只把入站改成回环 SOCKS，以隔离 REALITY 公网伪装目标的依赖。DNS 将 `public-routing.test` 固定为公网地址，实际请求目标为回环 HTTP 服务；请求 Host 故意使用该公共域名。旧 `destOverride=['http','tls','quic']` 下，`127.0.0.1` 和 `localhost` 两种实际目的地都收到请求并返回专用标记；新 `destOverride=[]` 下两者都未收到请求、客户端也未得到标记。四项符合预期，脚本 4.188 秒退出 0。此机制复现没有借公网失败充当拒绝证明，也不代替三协议完整 E2E。

### 邀请历史、消费债务与账期的区别

最近 100 条列表是展示接口，不是活动承诺的完整集合。预留预算和待用码上限现在直接查询活动记录，回归特意制造 101 条后续撤销记录，再兑换仍有效的旧码。该问题不依赖管理员权限。

删除消耗过额度的下级现在把其预算内消费转移到邀请者累计中；日流量历史不再加一份。管理员删除仍会拆除直接邀请关系，存续后代的未来预算应由管理员决定。此修复能保留当时可见的消费债务，不能从已经丢失的历史、独立重置日或管理员手工清零反推不可变账本。当前累计计数不应宣称精确计费。

### 0.2.1 线路报告的线上契约

客户端按协议与服务器 host 聚合健康状态；请求仍为 `POST /s/<token>/api/report`，带 `X-V2V: 1` 和 JSON `{line, ok, host}`。`line` 为 `hy2`、`reality` 或 `tuic`，`ok` 为布尔值，不增加必填 server_id。服务端保存 `用户ID@规范化主机`，单独恢复一个主机不会清除另一个主机的故障；告警仍按不同账户数计数。无主机的旧版恢复请求仅在不存在歧义时接受。新版 HTTP 426 提示保留，客户端的 HTTPS 验证不能用关闭 TLS 来代替。

## 验证记录

### 本地执行命令

```sh
python -m unittest discover -s tests -t . -p 'test_*.py' -v
python -m compileall -q vps2vpn tools deploy tests
node --test tests/test_frontend.js tests/test_ui.js
bash -n install.sh deploy-mac.command tests/vps_acceptance.sh
pwsh -NoProfile -File tests/test_deploy_powershell.ps1
git diff --check
V2V_E2E_TARGET=www.amd.com python tests/e2e_local.py <fixed-core-binaries-directory>
```

| 层级 | 实际状态 | 证据范围 |
| --- | --- | --- |
| Python 全量回归 | Python 3.12.14：271 项，97.207 秒，全部通过 | 含 S25 的 2 项 HTTPS 线路回归；此轮进程加载早于最后 CLI 新增 2 项和旧长密码兼容回归，后者另见下行；完整新套件由本次 CI 再验证。 |
| 新增通知归属/并发 | 3 项通过 | 禁用期间返回的长轮询、API 失败重试、并发同 key；没有调用真实 Telegram。 |
| CLI / Web 凭据发布及密码基础测试 | 11 项通过，3.052 秒 | 最终验证端兼容旧长密码后执行：凭据发布 7 项、旧长密码真实 HTTPS 登录/迁移 1 项和基础密码/X25519 3 项。新设置 129 字符拒绝且不修改原身份，既有更长密码仍可验证并改为新密码；会话撤销失败时整个改密回滚。 |
| 真实本地 CA / HTTPS | 通过 | 独立连接地址与证书域名，受信链/主机名校验、订阅和核心一致性；不是公网 ACME 签发。 |
| Node | 7 个测试入口通过 | 原 6 项及新 `test_ui.js`，含额度、刷新、事件、图表和日期；不是桌面浏览器渲染验收。 |
| Python 编译、Bash 语法、diff 空白检查 | 通过 | 包含生产、部署和全部测试目录。 |
| PowerShell | 通过 | 实际 PowerShell 执行的语法、分片秘密过滤、SSH 参数验证；不是 Windows 图形部署。 |
| ShellCheck | 本地未安装 | PR CI 保留相同检查，没有用 `bash -n` 冒充 ShellCheck。 |
| 固定版本配置解析 | 通过 | Xray 26.3.27、Hysteria 2.14.0、sing-box 1.14.4、Mihomo 1.19.34 的实际二进制。 |
| 完整真实内核 E2E | 本地未通过：12 通过、9 失败后异常退出 | 当前执行容器拒绝 netlink socket，sing-box 报 `operation not permitted`；外网直连也不通，代理公网正控制失败。TUIC 第二阶段客户端未启动，ConnectionRefused 后保留 traceback/日志。不得把这次结果写成 56 项通过。 |
| 安装、生产网络与移动端 | 未在当前工作区执行 | 通过 PR CI 在隔离 Linux runner 验证安装/真实内核；其他平台/公网场景仍需单独验收。 |

第一次续审全套 257 项发现 AI 汇总误报、Xray 嗅探覆盖及恢复测试夹具未同步流量关联 ID；均已定位并修复。第二轮仅余新增探测对应的框架预期，未删除失败断言或跳过失败用例。完整最终 CI 必须绑定本次代码提交；先前报告的 176 单测、44 项 E2E、45 项安装验收仅属于其注明的历史提交。

## 仍有边界、后续建议

1. **TUIC 归属和跨节点观测窗口。** 全局总计和当前连接不能还原已结束的多用户短连接；按权重归属仍是估计。远端旧版本无 epoch、备份回退、删除前最后采样间隙也不能保证精确恢复全部字节。本次未伪造缺失流量。
2. **账户账期。** 新事务及排序消除了同轮旧快照、并发重置和 ID 顺序缺陷；独立重置日、跨月长期停机、手工清零和预算迁移仍需产品明确不可变账本语义。不能保证字节级实时硬截止。
3. **首次订阅信任。** 自签部署的 HTTP 兼容订阅仍含访问凭据，首次获取必须由可信渠道分发或使用可信证书。客户端更严格的 TLS 不能让已泄露的首次明文请求重新保密。
4. **证书发布。** 同进程读写锁和 staging 隔离已实现，两个文件不是跨进程/断电事务；生产 ACME 挑战、外部反代及客户端 pin 迁移没有真实公网站点验收。
5. **资源和性能。** HTTP 有读取截止点、线程和正文上限，但 DNS、后台外部 API、业务操作和响应输出不共享全链路预算。未凭本地回环速度宣称公网吞吐提升，未改没有实验收益的 QUIC 窗口。
6. **平台和权限。** netlink/nft/systemd、云防火墙、Windows/macOS 桌面交互和 Android 真机 TUN 需相应系统执行。当前容器的权限失败是明确未验证项，不能用单元替身替代结论。

## 依据和可审查性

- [Telegram Bot API：getUpdates / offset / ok](https://core.telegram.org/bots/api#getupdates)；负 offset 读取尾部，API 返回 `ok` 决定成功，私聊身份与每次命令处理前的本地授权另外校验。
- [Python HTTPResponse](https://docs.python.org/3/library/http.client.html#httpresponse-objects)；将 HTTP 状态、正文边界和 `HTTPException` 纳入监控/通知边界。
- [Xray sniffing](https://xtls.github.io/config/inbound.html#sniffingobject) 与上文固定提交源码用于核对 routeOnly 的实际行为。
- 前次 [后端报告](backend.md) 的原子文件、节点身份、统计 epoch、备份恢复等根因仍适用；本文件更新其曾列为未解决但本轮已修的部分。

完整实现、测试和报告均随 PR 提交；本报告不是补丁的替代品。没有合并 PR、修改默认分支、部署用户 VPS、发送 Telegram/邮件或上传真实用户备份。
