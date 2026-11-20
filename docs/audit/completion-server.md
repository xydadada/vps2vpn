# 服务端完整审计、整合修复与验证记录

日期：2026-11-20。**本文件是本轮最终整合的报告；此前 `2026-11-20.md`、`backend.md` 保留其历史基线、失败过程与 CI 证据，不应把旧结果当作此提交的结果。**

## 基线、范围与交付

本分支从默认分支 `main` 的 `65425087c628585379cdc17f3919f4ff17a32fad` 创建；保留该提交的 **0.2.1 版本、按账户/主机分别记录的线路恢复状态及会员 API HTTPS 要求**。整合服务端历史 [PR #1](https://github.com/xydadada/vps2vpn/pull/1) 与 [PR #2](https://github.com/xydadada/vps2vpn/pull/2) 的有效修复，并实际复现和处理整合后的残余问题。没有合并 PR、修改默认分支或部署用户 VPS。

审阅范围包括全部自有生产 Python 模块、静态 HTML/JS/CSS、安装器和三种桌面部署入口；从 HTTP 请求、认证、SQLite、邀请配额、后台采集/执行、集群同步到三核心生成配置和客户端订阅，逐路径检查共享状态和信任边界。测试代码和 CI 的审阅/执行范围单独标注，避免把“跑过”冒充逐行阅读。文件清单、当前 SHA-256、基线 blob 和审阅类别见 [completion-coverage.tsv](completion-coverage.tsv)。第三方内核只审阅必要协议契约和调用边界，不声称完整审计上游实现。

完整可审查实现由本 PR **Files changed / Git Diff** 提供；本报告只解释问题、决策、验证和边界。运行逻辑没有依赖报告文件。

## 调用链与应保持的不变量

管理/会员/节点 HTTP 请求先验证 framing 和对象，认证后进入同一 SQLite 事务体系。凭据修改和会话撤销必须属于同一状态变化；延迟完成的旧认证不能重新发放已撤销身份。账户、赠额、邀请码和审批遵循“完整提交或完整回滚”，通知及核心重载在提交之后进行。

流量从内核采样到本地计数/日历史；跨节点累计值通过检查点转换为增量。**用量与该增量的检查点必须同事务**，否则重试会重记。月重置先基于真实账期执行，再按邀请关系从后代到祖先判定配额。核心配置写入、校验与服务启停串行执行；重复 Web 请求合并，但不能丢掉正在执行期间的新变更或 force 请求。

TLS 信任必须在发送凭据前建立。没有证书 pin 时正常验证 PKI；有 pin 时先校验叶证书。staging 与自签证书不能被误报为可信公网证书。订阅无节点和私网拒绝都必须保持拒绝行为，不得意外直接连接。

## 确认的问题、位置、影响及修复

位置格式为 **最新 main 基线行号 → 本次修复后行号**；函数名是稳定锚点。新增函数的基线列显示“函数锚点”。严重程度描述实际触发影响；管理员恢复、节点密钥等授权前提在相关说明中保留。历史发现的详细复现见 [backend.md](backend.md) 和 [2026-11-20.md](2026-11-20.md)，但发生差异时以下整合决策为准。

| ID | 级别 | 文件/函数与行号 | 原因、影响与实际处理 | 回归证据（位于 tests） |
|---|---|---|---|---|
| S01 | 高 | `vps2vpn/web.py` `Handler._read_body`；225 → 307 | 歧义 CL/TE、负数 chunk、截断和无限 trailer 会混淆请求边界或阻塞连接。完整解析后才进入写路径；严格拒绝非法 framing、非对象/非有限 JSON，限制总长度。 | `test_audit_web.py; test_audit.py` |
| S02 | 高 | `vps2vpn/web.py` `_RequestReader`；函数锚点 → 133 | 单次 socket timeout 可被持续滴流重置。每个请求从开始读头起设置绝对 20 秒读预算；接收线程最多 128 个，失败和结束均归还名额。 | `test_completion_server.RequestDeadline; test_audit_web.py` |
| S03 | 高 | `vps2vpn/web.py` `Handler.rate_limited`；461 → 600 | 并发认证预留缺失、成功请求清空同 IP 其他失败，均可放宽爆破预算。锁内预留唯一尝试，成功只移除本次预留；单调时钟和有界记录。 | `test_audit.py; test_audit_web.py` |
| S04 | 高 | `vps2vpn/web.py` `Handler.api_login`；511 → 690 | 校验密码期间密码/用户名/TOTP 可变化，旧请求随后重新签发有效会话。签发前事务内比对完整认证快照；会员、改密同样处理，拒绝为已删除用户创建会话。 | `test_completion_server.AuthenticationSnapshots` |
| S05 | 中 | `vps2vpn/web.py` `Handler.api_password`；1053 → 1259 | 改密未统一撤销会话；修改型接口可用 GET；错误日志和 CSV 含敏感数据/公式。密码轮换与撤销原子完成，动作只允许 POST，日志隐藏令牌，CSV 转义公式。 | `test_audit_web.py; test_admin.py` |
| S06 | 高 | `vps2vpn/db.py` `transaction`；函数锚点 → 208 | 单 SQL 锁不能覆盖检查后更新，嵌套失败可残留部分状态。引入共享可重入事务/保存点，处理 SQLite 已自动回滚的异常；注册、审批、批量增额/创建和用户复合修改均同事务。 | `test_audit_backend.py; test_audit.py; test_completion_server.StateAndTransport` |
| S07 | 高 | `vps2vpn/members.py` `given_away`；66 → 107 | 耗尽/暂停子账户可退回已消费赠额，祖孙链与深链扩大问题。按整数 bytes 迭代后序计算已消费/承诺用量，封顶原 grant；个人已消费额度不能再次承诺，容量向下舍入。 | `test_audit_backend.py; test_audit.py` |
| S08 | 高 | `vps2vpn/db.py` `delete_user`；310 → 344 | 删除受赠账户会抹去对邀请者的已消费负担。事务中保留子树已消费债务到邀请者计数，最多原 grant，不重复写物理流量历史；保留管理员拆除后代关系语义。 | `test_audit.py` |
| S09 | 高 | `vps2vpn/jobs.py` `enforce`；43 → 75 | 月重置、并发流量和限额更新可交错；按 ID 排序不等于邀请依赖顺序。先原子执行全部重置，再按真实邀请图子先父后判断，提交后才通知。 | `test_ops_audit.py` |
| S10 | 中 | `vps2vpn/jobs.py` `monthly_reset`；36 → 36 | 离线跨月后、在下一重置日前恢复会漏重置；新账户首次调度抹掉新流量；时钟回退可再次重置。按当前账期和上次账期比较，未重置账户以创建账期为基线。 | `test_completion_server.StateAndTransport; test_ops_audit.py` |
| S11 | 高 | `vps2vpn/db.py` `import_all`；458 → 716 | 恢复缺少关系/类型约束、历史表和会话清理，失败可损坏现有数据。先完整验证全部表和嵌套设置，事务替换；历史往返、旧格式兼容和会话失效；支持最新 main 的 uid@host 报告。 | `test_audit_backend.py; test_completion_server.StateAndTransport` |
| S12 | 高 | `vps2vpn/cluster.py` `handle_sync`；79 → 91 | 坏快照部分应用/删用户，省略 master_id 绕过绑定，重复 UUID 可能使内核身份歧义或失效。完整校验后事务替换；严格绑定身份；拒绝重复 UUID 和本地账户冲突。 | `test_audit_backend.py; test_completion_server.StateAndTransport` |
| S13 | 高 | `vps2vpn/cluster.py` `_request`；137 → 176 | 缺少 pin 时先使用不验证 TLS，可能先发送 node key/账户。无 pin 正常 PKI；有 pin 先验证叶证书再发凭据，CA 验证可接续合法续期；URL/响应有界。 | `test_audit_backend.ClusterTLS; test_audit.py` |
| S14 | 高 | `vps2vpn/cluster.py` `sync_one`；186 → 245 | 流量入账与检查点分开提交导致重试重复记账，旧快照可覆盖并发编辑。单节点增量/历史/检查点原子提交并重读记录；有界计数和可选 traffic_epoch 识别重置。 | `test_audit_backend.py` |
| S15 | 高 | `vps2vpn/cores.py` `xray_config`；26 → 39 | 仅 IP 规则不能检查域名目标；routeOnly 仍让嗅探 Host/SNI 改变路由判断，可绕过实际目的地址私网限制。Xray 用 IPOnDemand 且不覆盖嗅探目的地；TUIC 先 resolve 再 private reject。 | `test_ops_audit.py; test_audit_backend.py; e2e_local.py` |
| S16 | 中 | `vps2vpn/cores.py` `apply`；163 → 192 | 启用未变配置时核心保持停止；systemctl/nft 失败被视为成功；并发应用争用文件。完整应用串行、停服恢复、检查退出码；Web 合并重复 apply 并保留 force/后续请求。 | `test_apply_audit.py; test_audit_backend.py` |
| S17 | 中 | `vps2vpn/cores.py` `hysteria_config`；60 → 75 | 空账户表被固定版 Hysteria 拒绝而崩溃重启。空态使用基于随机 stats_secret 且独立域派生的稳定内部占位密码，不进入订阅；有用户后恢复真实表。 | `test_audit_backend.py; e2e_local.py` |
| S18 | 中 | `vps2vpn/cores.py` `TuicMeter`；225 → 273 | 暂时失败后重计、并发乱序、取整丢字节、暂停用户排除导致归属错误。串行采样、保留失败基线、整数最大余数守恒、保留全部现存用户，清除已删除权重。 | `test_audit_backend.py` |
| S19 | 中 | `vps2vpn/cores.py` `_local_json`；函数锚点 → 227 | 统计 HTTP 请求可能使用环境代理或泄漏响应句柄。loopback 专用无代理 opener，8 MiB 上限，上下文关闭，明确处理 HTTPException。 | `test_completion_server.StateAndTransport; test_ops_audit.py` |
| S20 | 高 | `vps2vpn/certs.py` `trusted`；93 → 119 | 只凭 SAN/期限会把不可信 staging 链当公网证书；选择忽略 self 模式。验证公开链、主机、期限和私钥匹配，缓存两文件纳秒时间戳；staging 分离存储，所有调用传所选模式。 | `test_ops_audit.py; test_completion_server.StateAndTransport` |
| S21 | 中 | `vps2vpn/certs.py` `ensure_self_signed`；55 → 69 | 缺/损坏私钥、自签主机标记、IPv6 SAN、fullchain 指纹和并发读取问题。校验证书对、规范地址、明确叶指纹，进程内可重入锁，IPv4-only 挑战限定回退；签发后强制应用。 | `test_audit_backend.py; test_ops_audit.py` |
| S22 | 高 | `vps2vpn/subscription.py` `clash`；138 → 158 | 没有可用节点的订阅回退 DIRECT，用户期望代理的流量会直连。Clash、sing-box、Shadowrocket 空态明确拒绝；非空格式保持协议。 | `test_audit.py` |
| S23 | 中 | `vps2vpn/subscription.py` `nodes`；58 → 65 | 节点/固定组重名、共享后配额仍报原额度、有限零额度显示无限。统一命名空间、有效额度与有限零余额标识；前端用同一 quotaUsage 语义。 | `test_audit_backend.py; test_ui.js` |
| S24 | 高 | `vps2vpn/system.py` `public_ip`；226 → 235 | 公网 IP 探测关闭 TLS、信任无界任意响应，会污染节点地址。恢复 PKI，限长并验证正确地址族的全球可路由 IP。 | `test_audit_backend.py` |
| S25 | 中 | `vps2vpn/system.py` `port_hopping`；130 → 135 | nft 删除后增加存在空窗，失败留半配置；内存页数假设 4 KiB。先校验后单批事务替换，错误可见，采用实际 SC_PAGE_SIZE；放行说明仅列必要端口。 | `test_ops_audit.py` |
| S26 | 中 | `vps2vpn/paths.py` `write_atomic`；52 → 53 | 共享固定临时名和一次 os.write 会引入并发冲突/短写。相邻唯一临时文件、完整写、fsync、权限后原子替换；失败不破坏旧文件。 | `test_audit_backend.py` |
| S27 | 中 | `vps2vpn/monitor.py` `run_in_background`；195 → 199 | socket/HTTP 句柄异常泄漏，重复后台探测排队，线程启动失败卡死。上下文清理、启动前单飞占位和失败释放；规则刷新采用同类处理，超大规则拒绝发布。 | `test_ops_audit.py; test_completion_server.StateAndTransport` |
| S28 | 高 | `vps2vpn/notify.py` `bot_loop`；84 → 85 | 群聊中的命令和启动前旧消息可能被误执行。限制配置的私聊身份，初始化游标跳过积压命令，只有新消息进入命令处理。 | `test_ops_audit.py` |
| S29 | 中 | `vps2vpn/secure.py` `check_password`；34 → 34 | 损坏 PBKDF2 工作参数/超长输入引发异常或过大计算。边界检查、失败关闭；登录和改密长度一致，保留现有密码兼容范围。 | `test_completion_server.AuthenticationSnapshots` |
| S30 | 高 | `deploy/deploy.py` `save_record`；84 → 85 | 部署记录含管理密码；固定临时名、权限设置失败被忽略、写前权限空窗。唯一私有临时文件、写前 ACL、原子替换；Windows ACL 失败拒绝发布。PowerShell 同样实现 File.Replace/Move。 | `test_audit_deploy.py; test_deploy_powershell.ps1` |
| S31 | 高 | `deploy/deploy.ps1` `Read-New`；126 → 135 | stdout/stderr 混用行缓冲，分片 UTF-8/凭据标记被打断可泄漏 V2V_RESULT。两流独立解码和行缓冲，结果只取 stdout，完整行过滤任意位置标记；工作目录先限制 ACL。 | `test_deploy_powershell.ps1` |
| S32 | 中 | `deploy/deploy.py` `run_job`；323 → 342 | SSH 挂起/异常缺少总时限及清理；QUIC IPv6/无关回复可误判。20 分钟安装截止、探测截止、异常 kill/wait/关闭管道/删临时秘密，UDP connect 固定期望对端。 | `test_audit_deploy.py; test_deploy.py; test_deploy_powershell.ps1` |
| S33 | 高 | `deploy/deploy.py` `ssh_base`；296 → 309 | 临时 known_hosts 使每次连接都重新 TOFU，部署目标和面板 URL 输入不足。三入口持久私有 known_hosts；严格主机/端口/用户校验；面板必须 HTTPS、禁止跨目标跳转。 | `test_deploy.py; test_deploy_powershell.ps1` |
| S34 | 中 | `install.sh` `fetch`；函数锚点 → 函数锚点 | 应用替换/依赖校验/服务失败会留下半次升级，下载校验变量间接读取难核对。固定 SHA 架构选择，应用目录失败回滚，关键命令退出码和服务状态明确；保留卸载数据策略。 | `test_ops_audit.py; tests/vps_acceptance.sh; CI install` |
| S35 | 中 | `vps2vpn/bench.py` `run`；94 → 162 | 隐含 NO_PROXY 绕过、下载异常仅显示 0、上传非整 MiB 少发、诊断可能暴露 URL。显式代理、有界且去秘密的阶段错误、确切上传长度、受控测速 origin；CLI 默认验证 TLS、限长/限重定向。 | `test_audit_tools.py; test_audit.py; e2e_local.py` |
| S36 | 中 | `vps2vpn/static/app.js` `dateStr`；函数锚点 → 函数锚点 | UTC 显示/本地保存导致日期漂移；重复刷新、失效 DOM、观察器/媒体事件泄漏。统一本地日期，单次在途刷新、页面失效检查，释放 observer，事件只注册一次。 | `test_frontend.js; test_ui.js` |
| S37 | 中 | `vps2vpn/aicheck.py` `summary`；207 → 207 | Claude API 可达但网站 unknown 时误报整体可用，影响 AI 节点选择。保守合并网站/API 结果，不以一个成功覆盖未知/失败；缓存按 0600 发布。 | `test_ops_audit.py; test_audit_tools.py` |
| S38 | 中 | `tests/e2e_local.py` `main`；94 → 247 | finally 退出吞异常、隐含代理绕过和公共限流让测试证据失真。保留异常非零状态，真实显式代理/受控下载上传，私网目标阳性对照和 Host 伪装用例，失败日志可定位。 | `test_audit_tools.py; CI e2e` |

## 整合中的关键取舍

1. **没有以较弱实现覆盖较强实现。** 保留第一轮的完整备份关系验证、历史往返、流量 epoch、真实固定核心 E2E、显式测速代理和受控 origin；合入另一轮的认证预留所有权、后台单飞、配额事务、通知身份和安装回滚。新 main 的报告结构进入恢复验证器，旧 `uid` 与新 `uid@host` 都能恢复。
2. **邀请保留额是至少 1 GiB 总个人额度，不是已用额度外再扣 1 GiB。** 10 GiB 账户已用 8 GiB，尚无其他分配时可以再分享 2 GiB。保留 `max(1 GiB, 已用)`，兑换时重新验证；测试按这一既有契约修正。删除受赠账户保留已发生的消费，不猜测历史已删记录。
3. **账期以重置日定义。** 15 日重置、10 月已重置，离线到 12 月 3 日恢复时补进 11 月账期；第二次执行不再清零。新账户不因首次运行被清零。时钟回退只影响等待时间，不能制造额外重置。旧测试显式设置过去 `last_reset`，保证仍在真实测试“重置发生”而不是依赖错误的创建即重置行为。
4. **Xray 嗅探仍可识别协议，但不以 Host/SNI 改写目的地址。** `routeOnly` 只保持原拨号目标，不能阻止路由规则使用嗅探域名；因此保留 `IPOnDemand` 并令 `destOverride` 为空。E2E 额外验证把公网 Host 放在 loopback 目的地址上的请求被拒绝，生产配置不加入私网例外。
5. **Windows 秘密文件先私有后写入。** PowerShell 真正执行同目录 File.Replace；跨流 UTF-8 增量解码、完整行过滤和结果通道独立。所有 ACL 失败可见，不能以写完后 chmod/忽略 icacls 错误代替安全发布。
6. **没有依据回环数字调整公网算法。** 不改未经跨网络验证的 QUIC 拥塞参数、协议排名或“智能”权重。空态拒绝、少做重复任务、限制资源和正确释放句柄有直接正确性/可靠性收益；未宣称提升公网吞吐。

## 本次验证

最终验证命令：

```sh
python -m unittest discover -s tests -t . -p 'test_*.py' -v
python -m compileall -q vps2vpn tools deploy tests
node --check vps2vpn/static/app.js
node --check vps2vpn/static/kit.js
node --check vps2vpn/static/member.js
node --test tests/test_frontend.js tests/test_ui.js
pwsh -NoProfile -File tests/test_deploy_powershell.ps1
bash -n install.sh deploy-mac.command tests/vps_acceptance.sh
git diff --check
```

| 层级 | 本轮实际结果与证据边界 |
|---|---|
| Python 3.12.14 完整 unittest | 275 项通过，84.852 秒，OK；本地完整日志 `server-complete-tests.log`。包括旧/新审计、最后四个账期/UUID 回归和三项部署失败清理回归。日志位于审计工作区；PR CI 提供远端可复核记录。 |
| 残余问题专项 | 53 项通过，覆盖过期认证快照、删除用户会话、总请求读截止、账户批量回滚、规则长度、模式选择、账期/UUID 碰撞，以及运维与事务并发。已包含于最终全量执行。 |
| 前端 | Node 共 7 个 TAP 测试条目通过（6 个独立前端回归 + 1 个 UI 文件级测试）；覆盖本地日期、离开页面的 spark/observer、单次媒体事件、401 DOM、刷新不重叠和有限零配额。 |
| PowerShell | PowerShell 7 下真实解析部署脚本并执行流分片、跨流凭据隐藏、UTF-8、私有写入顺序、原子替换、模拟 ACL 拒绝和 SSH 输入验证；通过。Windows 原生 icacls/Forms 未在 Linux 执行。 |
| 语法/格式 | Python compileall、三 JS node --check、三个 Shell bash -n、Git whitespace 检查通过。 |
| 固定真实内核 E2E | 本地缺少固定 Xray/Hysteria/mihomo/sing-box 二进制，未伪报本次通过。PR 的 `e2e` job 执行三协议 × 两客户端、私网/localhost/Host 伪装拒绝、空账户认证、统计、受控下载上传。以该 PR 提交对应 CI 结果为准。 |
| 安装/系统 | 本地不模拟生产 root/systemd 安装。PR `install` job 在独立 Ubuntu runner 跑真实安装、初始化、服务/权限、升级、卸载保留数据及重装验收。 |
| Shellcheck / Python 3.8 | 本地没有相应可执行工具；CI 保留 Shellcheck 和 Python 3.8/3.12 矩阵。旧 PR 的通过记录属于旧提交，不能替代这次 CI。 |

测试曾揭示并修正三个真实整合差异：Claude 网站 unknown 被 API ok 覆盖；Xray routeOnly 不能阻止 Host 路由伪装；恢复用户 ID 的夹具忘记同步 remap 流量引用，触发更严格验证器。最后一种修复的是夹具，未放松生产约束。部署测试使用真正的 urllib opener mock 和不可解析测试域，避免意外请求公共服务。

## 与配套客户端的契约

配套 [vps2vpn-client](https://github.com/xydadada/vps2vpn-client) 的本轮 PR 在服务端 PR 描述中关联。服务端保留订阅格式与 `/s/<token>/api/me`、`/report` 字段；会员 API 继承 main 的 HTTPS 要求。客户端可从 HTTP 订阅来源推导同主机同端口 HTTPS API，只能复用与同一 TLS 终结点匹配的 HY2/TUIC pin；没有 pin 则验证正常 PKI。不能根据一个任意异地主机的订阅节点把全局 TLS 验证关闭。

服务端生成“无节点即拒绝”的订阅；客户端另行拒绝无效配置覆盖正在运行的代理规则。这是两个独立边界，不能用一侧修复代替另一侧。主节点/子节点 `traffic_epochs` 为可选字段，不影响消费订阅的客户端；旧节点仍保留兼容读取路径。

## 尚未解决的边界与需要部署环境的验证

- **首次订阅信任**：兼容已有客户端的 HTTP 订阅入口仍含 bearer URL 与节点凭据。有效会员 API 在 HTTP 返回 426，但不能据此声称 HTTP 订阅机密。需要可信证书或可信渠道分发；不能从首次未认证下载凭空建立信任。
- **计量信息不足**：TUIC 仅全局计数和当前连接，采样间结束的多用户短连接无法精确归属；已修人工重复/丢余数，不提供计费级保证。旧节点无 epoch、离线末尾流量和备份回退也无法还原未观测字节。
- **管理员改变预算的语义**：管理员独立调整父子重置日、手动清零、给子账户另加额度，仍不是不可变周期账本；历史已删消费无从补录。本轮普通用户反复赠送、删除当前受赠用户抹去已耗债务、月重置竞态已关闭，未捏造跨历史周期的财务一致性。
- **证书对跨进程原子性**：进程内锁、有效性/模式/staging 检查已完成；证书和私钥仍是两个独立替换文件。独立核心读文件、机器断电或进程外人工更新不具有文件组事务保证。真实 ACME、反向代理、自签转公网 pin 更新需要实际部署验证。
- **操作系统和真实网络**：原生 Windows ACL/Forms、macOS 启动权限、移动端 VPN/TUN 和公网 NAT/多地址 DNS/断网切换/长期负载未在当前 Linux 会话完成。现有平台静态和协议测试不能代替真机验收。
- **强截止与密码实现**：HTTP 已有总读截止和线程上限，但内核采样/同步/配置应用是周期工作，限额不是按字节实时硬截止。纯 Python X25519 不声称恒时；固定上游依赖未逐行全审。

以上明确区分环境缺口、上游观测能力与产品账本语义，未将无法验证写成“全部正常”。当前已复现且能在仓库内安全关闭的问题均包含修复与回归；后续验收不能省略真实内核和安装 CI。

## 核对的机制资料

- [Xray inbound sniffing / routeOnly](https://xtls.github.io/config/inbound.html)：嗅探如何改变路由目标；审阅对应字段与现有固定版本生成配置。
- [Xray routing / IPOnDemand](https://xtls.github.io/en/config/routing.html)：IP 规则在需要时解析域名的条件。
- [RFC 9112 请求体长度规则](https://www.rfc-editor.org/rfc/rfc9112.html#name-message-body-length)：CL/TE 歧义和不完整消息的处理。
- [Hysteria Traffic Stats API](https://v2.hysteria.network/docs/advanced/Traffic-Stats-API/) 与固定版本认证源码链接见历史后端报告。

来源解释机制，实际结论以本仓库测试、明确的本次运行结果和 PR Diff 为依据。
