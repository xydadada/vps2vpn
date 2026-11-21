# vps2vpn

**买一台 VPS，点一下，就有了自己的 VPN。**
Buy a VPS, click once, get your own private VPN. ([English below](#english))

- 不用懂网络：在自己电脑上双击「一键部署」，填 IP、拖进密钥，剩下的全自动（建账号、查防火墙、导入 VPN 软件、测 AI 能不能用）。
- 一个订阅链接通吃：Clash Verge / FlClash / Mihomo Party / Stash、Shadowrocket（小火箭）、Hiddify、sing-box、v2rayN/NG 都能一键导入。
- 三种协议随时切换、互为备份：**Hysteria 2**（UDP，丢包严重的晚高峰线路上最快）、**VLESS + REALITY**（TCP，伪装成访问大网站，最稳）、**TUIC v5**（UDP，Hysteria 被限速时的另一条 QUIC 路）。每种都能在面板里单独开关，App 里可手动挑，也会自动切到能用的那个。
- 管理面板沿用原来那套管理控制台的设计：侧边栏、实时流量曲线、每日用量柱状图、使用者抽屉（二维码、一键导入、用量圆环）、浅色/深色/跟随系统，手机上自动变成底部标签栏。
- 多用户：每人一个链接，可设流量上限、到期日、每月重置日；超额自动停用，续上自动恢复。
- 面板只依赖系统自带的 Python 3，不装 Docker、不装数据库、不加载任何第三方网页脚本。

> ⚠️ 请遵守你所在地和服务器所在地的法律法规。本项目用于保护个人隐私与网络安全。

---

## 买服务器之前（30 秒看完）

- **系统**：选 Ubuntu 22.04 / 24.04 或 Debian 12（最省心），最低 512 MB 内存就够一个人用。
- **地区怎么选**：
  - 只图**国内访问快**：香港、日本、新加坡、韩国（延迟低）。
  - 要**用 Claude / ChatGPT**：美国、日本、新加坡、英国、澳大利亚等都行；**香港用不了 Claude 和 ChatGPT**。部署完会自动测给你看。
  - 两样都要：买一台日本或新加坡的，或者两台（再部署一次选「加到第一台下面」）。
- **流量**：按月给流量的套餐（比如 AWS Lightsail 每月 1–2 TB），一个人看视频足够；面板里可以设「服务器月流量」上限，快用完会提醒。
- **登录方式**：云厂商一般给一个 SSH 密钥文件（`.pem`），下载保存好，部署时拖进窗口就行。
- **防火墙**：大多数云厂商默认只放行 SSH。部署工具会从你的电脑测试每个端口，挡住了就告诉你去控制台哪里点，不用提前设。

## 怎么用（三选一）

### 方法 1：电脑上一键部署（最傻瓜）

1. 下载本项目：打开 [Releases 页面](https://github.com/xydadada/vps2vpn/releases/latest) 下载 `vps2vpn-*.zip`（或者 GitHub 页面右上角 Code → Download ZIP），解压。
2. **Windows**：双击 `deploy-windows.bat`，弹出一个窗口——**什么都不用另外装**（用的是 Windows 10/11 自带的 PowerShell、tar 和 ssh）。
   **macOS**：双击 `deploy-mac.command`（第一次可能要右键 → 打开）。Linux：`bash deploy-mac.command`。
3. 填服务器 IP，把云厂商给你的 **SSH 密钥文件拖进窗口**（整个 `.ssh` 文件夹拖进去也行，会自动找到私钥），或者填 root 密码，点「一键部署」。
4. 等一两分钟，**剩下的全自动**：
   - 管理员账号和你的第一个 VPN 账号自动建好（不用再打开网页设置）；
   - 自动检测你电脑上的 VPN 软件（Clash Verge、FlClash、Mihomo Party 等），**自动打开它并导入**，分流规则（国内直连、国外走代理）已经写好；没装的话给你下载链接；手机扫窗口里的二维码导入；
   - 从你的电脑**测试云服务商防火墙**有没有放行每个端口，挡住了就告诉你去控制台哪里点、点什么，放行后点「再检查一次」；
   - 面板地址和管理员密码显示在窗口里，并保存在你电脑用户文件夹下的 `vps2vpn` 文件夹（只在你自己电脑上）。
5. **第二台、第三台服务器**：再部署一次，在「这台服务器怎么用」里选「加到 某某 下面」。它会自动加入第一台：共用同一套账号，你原来的订阅里自动多出这台，不用重新导入。

> 配套电脑客户端：[vps2vpn-client](https://github.com/xydadada/vps2vpn-client)（基于开源的 FlClash，默认界面更简单，能显示剩余流量、到期时间和 AI 可用性）。不想装也没关系，Clash Verge、FlClash 等现有软件都能直接用。

密钥和密码只用于这一次连接，用完立即删除，只发给你自己的服务器。（装了 Python 的话，也可以用浏览器版部署器：`python3 deploy/deploy.py`，功能一样；Mac 装了开发者工具时 `deploy-mac.command` 会自动用它。）

### 方法 2：在服务器上粘贴一行命令

用云厂商网页上的「浏览器 SSH / 控制台」登录服务器，粘贴：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/xydadada/vps2vpn/main/install.sh)
```

装完屏幕上会出现一个链接，打开它，后面同上。

它装的是最新的正式版（Release），下载后先核对 SHA256 校验值，对不上就拒绝安装。再次运行就是升级：升级前会先把数据库和旧版本代码存一份快照（保留最近 3 份），并打印一行回滚命令。

### 方法 3：已经下载了代码

```bash
sudo bash install.sh
```

### 打不开面板？

用方法 1 部署的话，部署工具会自动从你的电脑测试每个端口，并告诉你结果。

安装脚本能认出 AWS Lightsail / EC2、甲骨文云、谷歌云、Azure、阿里云、腾讯云，会直接告诉你去控制台哪个页面、点哪个按钮放行端口（这一步在服务器外面，脚本替你做不了）。

去云厂商控制台的 **防火墙 / 安全组** 放行这些端口（装完屏幕上和面板「系统」页都会列出具体端口）：

| 用途 | 协议 / 端口 |
|---|---|
| 管理面板 + 订阅 | TCP 随机高位端口（安装时显示） |
| 免费证书申请 | TCP 80 |
| VLESS + REALITY | TCP 443 |
| Hysteria 2 | UDP 443 和 UDP 20000-40000（端口跳跃） |
| TUIC v5 | UDP 8443 |

---

## 功能一览

**搭建**
- 一键安装脚本：Debian / Ubuntu / RHEL 系 / Fedora / openSUSE / Arch，x86_64 和 arm64。重复运行就是升级，用户和设置都保留。
- 核心程序从官方 GitHub Release 下载，并**逐个校验 SHA-256**。
- 自动挑选伪装网站：从服务器实测一批大网站，选支持 TLS 1.3 + HTTP/2 且最快的那个。
- **免费受信任证书**：自动向 Let's Encrypt 申请——**没有域名也行**（Let's Encrypt 从 2026 年 1 月起正式支持纯 IP 证书，有效期约 6 天，面板自动续期）。申请失败自动退回自签名证书，照样加密能用。
- 只有系统已开着 ufw / firewalld 时才去放行端口；不会擅自打开防火墙把你锁在外面。
- **端口被占用自动避让**：443 已经被 nginx / 其它面板占着，就自动换到 8443 / 2053 等空闲端口，并告诉你是谁占的。
- 小内存机器（< 1 GB）自动加 1 GB swap，自动开启时间同步（时间不准会导致连不上）。
- 升级失败自动回滚到上一个版本。

**网络调优（自动，不用填带宽）**
- 开启 BBR + fq；TCP/UDP 缓冲区按内存大小自动设定（512 MB 小鸡到 4 GB+ 分四档，防止内存被撑爆）。
- Hysteria 2 不写死带宽，交给 BBR 自适应；QUIC 接收窗口加大到适合 200–300 ms 跨洋线路的大小。
- UDP 端口跳跃：客户端在 2 万个端口间轮换，避开运营商对单个 UDP 端口的限速。
- **服务器端 DNS 自适应**：能连上加密 DNS（Cloudflare / Google / Quad9）就用加密 DNS，连不上就自动改用系统 DNS。以前遇到加密 DNS 被拦的机器，每个新连接要白等约 8 秒；在这种环境下实测，经 REALITY 的单次请求延迟中位数从 8.3 秒降到 0.38 秒。
- 订阅里的分流规则文件由**你自己的服务器镜像**下发，国内客户端更新规则不用翻墙、不怕 GitHub 抽风。

**订阅与分流**
- 按 App 自动识别格式（Clash / sing-box / 小火箭原生配置 / 分享链接），浏览器打开订阅链接就是这个使用者自己的会员页。
- **小火箭原生配置**：和 Clash 同一套分流规则（服务器自动转换成小火箭格式），一键 `shadowrocket://` 导入。
- 分组精简：节点选择、自动选择、AI 服务、国内服务、漏网之鱼。
- 国内网站、国内下载（Steam、苹果、微软、游戏 CDN）直连；国外走代理；可选屏蔽广告。
- **DNS 防泄漏**：国外域名的 DNS 查询经代理发往 Cloudflare / Google，运营商看不到你查了什么。
- 订阅头带流量和到期信息，App 里直接显示剩余流量。

**AI 专区（用 Claude / ChatGPT / Gemini 的看这里）**
- **AI 可用性体检**：从服务器上直接测 claude.ai 网页、Claude API、ChatGPT、Gemini 能不能用，结果写成「能用 / 地区不支持 / 连不上」；同时显示 IP 在哪个城市、哪家机房、是机房 IP 还是家庭宽带 IP。
- 一键部署完成时直接告诉你：**「这台服务器：Claude ✓ ChatGPT ✓ Gemini ✓」**；面板「体检与维护」里随时可以点「重新检测」。
- 每天自动复查一次，状态变了（比如 Claude 突然不让用了）发 Telegram 提醒；在 Telegram 里发 `/ai` 也能马上查。
- **AI 固定出口**：订阅里的「AI服务」分组专门管 Claude、ChatGPT、Gemini、Grok、Perplexity 这些网站。普通上网可以「自动选最快」，**AI 网站固定走同一台服务器**，不跟着来回跳。有多台服务器时，默认选 AI 体检结果最好的那台，App 里也能自己改。
- 一键部署时服务器自动用所在城市起名（例如「悉尼」），App 里看到的是「悉尼 Hysteria2」而不是一串数字。

> **给 Claude 用户的几句大实话**
> 1. 选服务器：美国、日本、新加坡、英国、澳大利亚等地区都能用 Claude；香港、中国大陆、俄罗斯等地区用不了。部署完看一眼体检结果就知道。
> 2. **固定一个出口**：登录 Claude 时尽量一直用同一台服务器，别今天美国明天日本。这就是上面「AI 固定出口」做的事。
> 3. 机房 IP（所有 VPS 都是）打开 claude.ai 时可能先做一次人机验证，浏览器里一般自动通过，不算被封。
> 4. **Claude Code 等命令行工具**不一定走系统代理。在终端里先设好代理再用，例如 PowerShell：`$env:HTTPS_PROXY="http://127.0.0.1:7890"`，macOS / Linux：`export HTTPS_PROXY=http://127.0.0.1:7890`（端口以你的 Clash 软件里显示的为准）。也可以在 Clash 软件里打开 TUN 模式，所有程序都会走代理。
> 5. 体检结果只作参考：账号会不会被封，还和付款方式、注册信息、使用习惯有关，本项目不承诺「防封」。

**管理面板**
- 一键部署工具自动建好管理员和第一个账号；手动安装时用首次设置向导（安装时生成一次性链接，别人抢不走）。
- 用户：增删改、暂停、清零流量、更换链接（旧链接立即失效）。
- **用户列表像成熟面板一样好管**：搜索、按状态筛选（在线 / 正常 / 已停用 / 7 天内到期 / 快用完）、按用量 / 到期日 / 最近使用排序；勾选多个人一次性启用、停用、延期、加流量、清零、换链接、删除；**批量添加**（一次建 200 个，名字自动编号）；**导出表格**（CSV，Excel 直接打开）。
- **设备数上限**：每人可限制同时在线几台设备，超了自动暂停 10 分钟（也可以只提醒不暂停），并记录是哪些 IP。
- **首次使用才开始计时**：比如「30 天」从他第一次连上那天算起，适合先发码、后使用。
- **自定义分流**：自己填「直连 / 走代理 / 屏蔽」的域名清单，Clash、sing-box、小火箭三种订阅一起生效。
- 概览：实时速度、在线数、内存、负载、30 天流量图、服务状态，**服务器 24 小时 CPU / 内存 / 网络曲线**（重启也不丢）。
- 备份 / 恢复（一个 JSON 文件），修改管理员密码，查看日志；**每天自动备份**到服务器，保留 14 天。
- **一键体检**：连不上或变慢时点一下，逐项检查服务、伪装网站、证书、BBR、UDP 缓冲、时间同步、IP 是否变了、服务器能否上外网、磁盘内存、规则更新——每一项不正常都直接告诉你怎么修。
- **自动看护**：代理挂了自动拉起；云服务器换了公网 IP，两次确认后自动把订阅改成新 IP（App 下次更新订阅就好了）。
- **Telegram 告警**（可选）：流量用到 80%、有人被停用、服务挂了、IP 变了、证书续不上，都会发消息给你。面板里贴上机器人 token、点「连接」就行。连上以后还能在 Telegram 里**发命令**：`/status` 看服务器状态、`/users` 看每人用量、`/user 名字`、`/doctor` 体检、`/ai` AI 可用性、`/backup` 要一份备份（只回复你自己）；**每天的自动备份也会发到 Telegram**，服务器整台丢了也能恢复。
- 可选同时提供 **IPv6 节点**：IPv4 线路卡的时候换着用。
- **会员中心**：每个使用者有自己的页面（随机路径 + 账号密码登录，或直接用浏览器打开订阅链接）：剩余流量圆环、30 天用量、一键导入、二维码、改密码。
- **邀请码**：管理员发的码（自带额度和有效期）；会员也能从自己的额度里分一份邀请朋友（有数量、次数、有效期上限，自己至少留 1 GB）。
- **申请加流量**：会员在页面上申请，管理员在面板里批准/拒绝，批准后被停用的自动恢复。
- **在线状态**：三种协议都能看到谁在线、几台设备、哪些 IP。
- **网站监控**：每 5 分钟从服务器测 GitHub、YouTube、ChatGPT（含地区是否被封）、Google、X、Telegram 的 IPv4 / IPv6 延迟和测速，保留 24 小时曲线。
- **防滥用**（只提醒、不自动封）：像扫描/当跳板、链接被很多人共用、大量发垃圾邮件时记一笔并发 Telegram。
- **服务器月流量**：按你的套餐设上限和重置日，用到 80% / 100% 提醒。
- **多台服务器合成一个订阅**：另一台装好 vps2vpn 后复制它的「加入码」贴到主面板，用户自动同步过去、流量自动汇总回来，订阅里每台服务器一组、自动切换。
- 中文 / English，自动深色模式，手机上也好用。
- **两步验证（2FA）**：可选，登录时再输入手机验证器 App 的 6 位数字，密码泄露也登不进来；**登录记录**（时间、IP、设备、成功/失败）和「退出其它所有设备」。
- 安全：PBKDF2 密码哈希、登录限速、HttpOnly + SameSite=Strict 会话、防跨站请求、严格 CSP、面板藏在随机路径下（直接访问端口只看到一个 nginx 404）。

---

## 实测（本项目的测试都是真程序真流量）

`python -m unittest tests.test_unit tests.test_features tests.test_admin tests.test_deploy tests.test_ops tests.test_telegram_pairing` —— 230 项离线测试：X25519 对照 RFC 7748 标准向量、二维码逐像素对照参考实现、用户限额 / 到期 / 月重置、备份恢复、完整的网页流程（设置向导、登录限速、跨站拦截、订阅格式识别）、邀请码额度计算、会员注册登录与申请审批、小火箭配置、防滥用判定、两台服务器之间真实 HTTPS（证书固定）同步、两步验证（对照 RFC 6238 标准向量）、批量操作、设备上限、自定义分流、Telegram 命令只认主人、一键部署（免向导建账号、保存的密码升级后不丢、从外部测 TCP/UDP 端口、证书固定登录主服务器并加入）、AI 可用性体检（模拟能用 / 地区封锁 / 断网三种情况）、AI 网站在三种订阅里都走「AI服务」分组、AI 体检最好的服务器排第一。

`python tests/e2e_local.py <放官方程序的目录>` —— 在一台电脑上启动**真的** Xray 和 Hysteria 服务端，再用**真的** mihomo（Clash 内核）和 sing-box 客户端发流量，共 28 项检查：

- 服务端配置被 Xray 自己的校验通过；REALITY 公钥与 `xray x25519` 结果一致
- 完整订阅被 `mihomo -t` 和 `sing-box check` 校验通过（含端口跳跃、混淆）
- mihomo、sing-box 两个客户端 × Hysteria 2、REALITY、TUIC 三种协议，六条路全部真实上网成功；TUIC 流量能准确记到对应使用者头上
- 每个用户的流量被两个核心正确计数；错误密码被拒绝
- 测速工具 `tools/bench.py` 能通过两个协议分别跑完
- 连接保持期间，三种协议都能正确识别在线用户和设备；防滥用扫描能读到流向；小火箭规则转换和配置生成；网站监控探测

**测试中发现的一个上游兼容问题**：Xray **v26.10.21 及更新版本**的 REALITY 服务端会拒绝 mihomo 1.19.34 和 sing-box 1.14.4 客户端的登录（Xray 自己的客户端不受影响）。v26.3.27 三种客户端全部正常。因为大多数人用的是 Clash 类 App 和小火箭，安装脚本**固定使用 Xray v26.3.27**，等上游修复后再升级。

**测速**（本项目不编造数字，你可以自己测）：

```bash
vps2vpn bench                                   # 在服务器上：服务器本身到外网的速度（VPN 不可能比它更快）
python tools/bench.py "你的订阅链接" --mihomo <mihomo程序路径>   # 在你电脑上：直连 vs 每个协议
```

电脑端会临时启动一个只监听本机的 mihomo，逐个协议测：延迟（每次都是全新 HTTPS 握手，中位数和 p90）、单连接下载、4 连接下载、上传，并和直连对比，可以 `--json` 存结果。不会改你电脑上的任何代理设置。

---

## 命令行（服务器上）

```bash
vps2vpn info              # 再次显示面板链接、证书状态、需要放行的端口
vps2vpn reset-password    # 忘了管理员密码
vps2vpn apply --force     # 重新生成配置并重启代理
vps2vpn cert              # 立即申请 / 续期证书
vps2vpn rules             # 立即更新分流规则镜像
vps2vpn sysctl            # 看本机会被设成什么内核参数
vps2vpn doctor            # 一键体检（和面板里的一样），--json 输出机器可读结果
vps2vpn bench             # 测服务器本身的网速
vps2vpn backup            # 立即备份一次（自动备份在 /var/lib/vps2vpn/backups）
bash install.sh uninstall # 卸载（保留数据）；加 --purge 连数据一起删
```

文件位置：配置和密钥 `/etc/vps2vpn`，数据库和规则镜像 `/var/lib/vps2vpn`，程序 `/usr/local/lib/vps2vpn`，内核参数 `/etc/sysctl.d/99-vps2vpn.conf`。

## 开发

```bash
python -m unittest tests.test_unit tests.test_features tests.test_admin tests.test_deploy tests.test_ops -v   # 离线测试
python tests/dev_server.py 8443           # 本机跑面板（开发模式，不动系统）
python tests/e2e_local.py ./bins          # 真程序端到端测试
sudo bash tests/vps_acceptance.sh --full  # 在一台可以随便折腾的真 VPS 上做验收（含重装、卸载再装）
```

`.github/workflows/test.yml` 在 GitHub 上自动跑：Python 3.8 / 3.12 单元测试、shellcheck、Linux 上的真程序端到端测试，以及在全新 Ubuntu 上真正运行安装脚本再跑验收。

面板只用 Python 标准库；前端是一个不依赖框架的 `app.js`。

## 路线图

- [x] 多台服务器合并成一个订阅（一个面板管多台 VPS）
- [x] 会员中心、邀请码、申请加流量
- [ ] 按用户限速（官方核心不支持，暂不做）
- [x] Windows / macOS 部署器不用装 Python
- [x] Telegram 告警
- [ ] 邮件告警
- [ ] 面板内一键升级核心

## License

MIT

---

<a id="english"></a>
## English

**vps2vpn** turns a fresh Linux VPS into a private VPN server with a web panel, for people who know nothing about networking.

**Install** – pick one:
1. *From your computer:* download this repo and double-click `deploy-windows.bat` (Windows 10/11, nothing to install) or `deploy-mac.command` (macOS/Linux). Type the server IP, drag in the SSH key file you got from your provider (or the whole `.ssh` folder, or type the root password), click **Deploy**.
2. *On the server:* `bash <(curl -fsSL https://raw.githubusercontent.com/xydadada/vps2vpn/main/install.sh)`
3. *From a checkout:* `sudo bash install.sh`

Then open the link it prints, set an admin password, click **Build my VPN**, and scan the QR code with your app.

The one-line installer installs the latest tagged release and checks its SHA256 before unpacking (developers: `V2V_REF=main` installs a branch, unverified). Re-running it upgrades; each upgrade first snapshots the database (SQLite online backup) and the previous code, keeps the last 3, and prints the one-line rollback command.

**What you get**
- Three protocols to switch between: Hysteria 2 (UDP, best on lossy routes), VLESS/REALITY (TCP, most robust) and TUIC v5 (UDP, a second QUIC option); clients fail over automatically.
- One link per user that works in Clash/mihomo apps, Shadowrocket, Hiddify, sing-box and v2rayN/NG; browsers get the user's own member page; native Shadowrocket config with the same rule sets.
- Member centre, invite codes (admin codes and member codes carved from the inviter's quota), quota requests with approval.
- Online users and devices for all protocols, site monitor (GitHub, YouTube, ChatGPT region, Google, X, Telegram; IPv4/IPv6; speed test), abuse guard that alerts but never bans, server monthly traffic cap.
- Several servers in one subscription: paste another server's join code; users sync over certificate-pinned HTTPS and traffic flows back into the same quota.
- Users with quotas, expiry dates and monthly resets, enforced automatically.
- Free trusted TLS certificates from Let's Encrypt, even without a domain (IP certificates, renewed automatically), with a self-signed fallback.
- Automatic tuning: BBR + fq, socket buffers sized to RAM, larger QUIC windows for long routes, UDP port hopping, no fixed bandwidth.
- Routing rule sets mirrored on your server; DNS for foreign sites goes through the proxy.
- AI zone: checks from the server whether claude.ai, the Claude API, ChatGPT and Gemini work (shown when a deploy finishes, in the panel, daily, and via Telegram `/ai`); subscriptions keep AI sites on one fixed server (the one with the best result) instead of following "Auto".
- Health check button (`vps2vpn doctor`) that tests every moving part and says how to fix what is broken; watchdog that restarts dead cores; automatic follow-up when the server's public IP changes; daily backups; optional Telegram alerts; optional IPv6 entries.
- Server DNS adapts: encrypted DNS when reachable, the system resolver otherwise (an unreachable DoH server used to add ~8 s to every new connection).
- Benchmarks you can run yourself: `vps2vpn bench` on the server, `tools/bench.py <subscription>` on your computer (latency median/p90 with fresh handshakes, 1- and 4-connection download, upload, next to a direct baseline).
- Standard-library Python panel: no Docker, no database server, no third-party scripts in the browser. PBKDF2, login rate limiting, strict cookies and CSP, panel behind a random path.

**Tested** with real Xray/Hysteria servers and real mihomo/sing-box clients (`tests/e2e_local.py`, 28 checks) plus 230 offline tests, and `tests/vps_acceptance.sh` for a real server. Xray is pinned to **v26.3.27** because v26.10.21+ rejects REALITY logins from mihomo 1.19.34 and sing-box 1.14.4.

**Ports to open** in your provider's firewall: the panel's TCP port (shown at install), TCP 80 (certificates), TCP 443 (REALITY), UDP 443 and UDP 20000-40000 (Hysteria 2), UDP 8443 (TUIC).

Please follow the laws that apply to you and to your server's location.
