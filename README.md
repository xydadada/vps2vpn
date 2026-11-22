# vps2vpn

**买一台 VPS，点一下，就有了自己的 VPN。**
Buy a VPS, click once, get your own private VPN. ([English below](#english))

- 不用懂网络：在自己电脑上双击「一键部署」，填 IP、拖进密钥，剩下的全自动（建账号、查防火墙、导入 VPN 软件、测 AI 能不能用）。
- 一个订阅链接通吃：Clash Verge Rev / FlClash / Mihomo Party / Stash、Shadowrocket（小火箭）、Hiddify、Karing、sing-box、v2rayN / v2rayNG，以及 Happ、Streisand 等都能导入。
- 三种协议随时切换、互为备份：**Hysteria 2**（UDP，丢包严重的晚高峰线路上最快）、**VLESS + REALITY**（TCP，伪装成访问大网站，最稳）、**TUIC v5**（UDP，Hysteria 被限速时的另一条 QUIC 路）。每种都能在面板里单独开关，App 里可手动挑，也会自动切到能用的那个。
- 适合分享给家人朋友：每人一个链接，可设流量上限、到期日、每月重置日；超额自动停用，续上自动恢复。还有邀请码和会员自助页面。
- 管理面板：实时流量、每日用量、使用者二维码、浅色/深色，手机上也好用。
- 面板只依赖系统自带的 Python 3，不装 Docker、不装数据库、不加载任何第三方网页脚本。

> ⚠️ 请遵守你所在地和服务器所在地的法律法规。本项目用于保护个人隐私与网络安全。

**目录**：[快速开始](#快速开始) · [添加使用者](#添加使用者) · [各平台怎么连](#各平台怎么连) · [升级与回滚](#升级与回滚) · [多台服务器](#多台服务器) · [Telegram 机器人](#telegram-机器人) · [常见问题](#常见问题) · [功能一览](#功能一览) · [命令行](#命令行服务器上)

---

## 快速开始

### 第 1 步：准备一台服务器

- **系统**：Ubuntu 22.04 / 24.04 或 Debian 12 最省心。也支持 RHEL 系、Fedora、openSUSE、Arch。CPU 是 x86_64 或 arm64 都行。
- **内存**：512 MB 就够几个人用（小于 1 GB 时会自动加 1 GB swap）。
- **地区怎么选**：
  - 只图**国内访问快**：香港、日本、新加坡、韩国（延迟低）。
  - 要**用 Claude / ChatGPT**：美国、日本、新加坡、英国、澳大利亚等都行；**香港用不了 Claude 和 ChatGPT**。部署完会自动测给你看。
  - 两样都要：买一台日本或新加坡的，或者买两台（见[多台服务器](#多台服务器)）。
- **流量**：按月给流量的套餐（比如 AWS Lightsail 每月 1–2 TB），几个人日常看视频够用。面板里可以设「服务器月流量」上限，快用完会提醒。
- **登录方式**：云厂商一般给一个 SSH 密钥文件（`.pem`），下载保存好。也可以用 root 密码。

### 第 2 步：在云厂商的防火墙放行端口

大多数云厂商默认只放行 SSH。去控制台的 **防火墙 / 安全组** 放行下面这些端口。这一步在服务器外面，安装脚本替你做不了。

| 用途 | 协议 / 端口 |
|---|---|
| 管理面板 + 订阅 | TCP 随机高位端口（安装时显示，在 40001–60000 之间） |
| 免费证书申请 | TCP 80 |
| VLESS + REALITY | TCP 443 |
| Hysteria 2 | UDP 443 和 UDP 20000-40000（端口跳跃） |
| TUIC v5 | UDP 8443 |

- 不确定面板端口？先装，装完屏幕上、`vps2vpn info` 和面板「体检与维护」页都会列出实际要放行的端口。
- 443 已经被别的程序占了，会自动换到别的空闲端口，以屏幕上显示的为准。
- 用一键部署（方法 1）的话，它会从你的电脑逐个测试端口，挡住了就告诉你去控制台哪里点。安装脚本也能认出 AWS Lightsail / EC2、甲骨文云、谷歌云、Azure、阿里云、腾讯云，直接告诉你去哪个页面放行。
- 服务器自己开着 ufw / firewalld 时，会自动在里面放行；没开就不动它（不会把你锁在外面）。

### 第 3 步：安装（三选一）

#### 方法 1：电脑上一键部署（最傻瓜）

1. 下载本项目：打开 [Releases 页面](https://github.com/xydadada/vps2vpn/releases/latest)，下载 **Source code (zip)**（或者 GitHub 页面上 Code → Download ZIP），解压。
2. **Windows**：双击 `deploy-windows.bat`，弹出一个窗口。**什么都不用另外装**（用的是 Windows 10/11 自带的 PowerShell、tar 和 ssh）。
   **macOS**：双击 `deploy-mac.command`（第一次可能要右键 → 打开）。Linux：`bash deploy-mac.command`。
3. 填服务器 IP，把云厂商给你的 **SSH 密钥文件拖进窗口**（整个 `.ssh` 文件夹拖进去也行，会自动找到私钥），或者填 root 密码，点「一键部署」。
   - 用户名一般不用改：亚马逊等服务器不让 root 登录、要求用 `ubuntu` 之类的用户时，部署工具会自动换成它（Mac 上没有 Python 时只会提示你改成什么）。
   - PuTTY 的 `.ppk` 密钥要先用 PuTTYgen 转成 OpenSSH 格式；设了密码保护的密钥不能用，部署工具会直接告诉你。
4. 等一两分钟，**剩下的全自动**：
   - 管理员账号和你的第一个 VPN 账号自动建好（不用再走设置向导）；
   - 自动检测你电脑上的 VPN 软件（Clash Verge、FlClash、Mihomo Party 等），**自动打开它并导入**，分流规则（国内直连、国外走代理）已经写好；没装的话给你下载链接；手机扫窗口里的二维码导入；
   - 从你的电脑**测试云厂商防火墙**有没有放行每个端口，挡住了就告诉你去控制台哪里点、点什么，放行后点「再检查一次」；
   - 面板地址和管理员密码显示在窗口里，并保存在你电脑用户文件夹下的 `vps2vpn` 文件夹（只在你自己电脑上）。

密钥和密码只用于这一次连接，用完立即删除，只发给你自己的服务器。（装了 Python 的话，也可以用浏览器版部署器：`python3 deploy/deploy.py`，功能一样；Mac 装了开发者工具时 `deploy-mac.command` 会自动用它。）

#### 方法 2：在服务器上粘贴一行命令

用 SSH 或云厂商网页上的「浏览器 SSH / 控制台」登录服务器。安装要 root 权限，不是 root 的话先切换：

```bash
sudo -i
```

然后粘贴：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/xydadada/vps2vpn/main/install.sh)
```

它装的是最新的正式版（Release），下载后先核对 SHA256 校验值，对不上就拒绝安装。装完屏幕上会出现一个带 `?setup=` 的链接，接着看第 4 步。

#### 方法 3：已经下载了代码

```bash
sudo bash install.sh
```

### 第 4 步：第一次登录（设置向导）

用方法 1 的跳过这一步，账号已经建好。

1. 浏览器打开安装完显示的那个**完整链接**（形如 `https://<你的服务器IP>:<面板端口>/<随机路径>/?setup=...`）。链接丢了：在服务器上运行 `vps2vpn info`。
2. 浏览器提示「不安全」是正常的：证书还没申请下来前用的是自签名证书，照样加密。点「高级 → 继续访问」。
3. 设好管理员用户名和密码（至少 8 位），填第一个使用者的名字，点「一键建好 VPN」，大约 10 秒。
4. 页面上出现订阅二维码和一键导入按钮，导入到 App 就能用了（见[各平台怎么连](#各平台怎么连)）。
5. **把面板链接收藏好**。面板藏在随机路径下，直接访问端口只看到一个 404。

登录时连续输错 8 次会锁定 10 分钟。

### 第 5 步：开启两步验证（建议）

面板「体检与维护」→「登录安全」→「开启两步验证」：

1. 用手机验证器 App（Google Authenticator、Microsoft Authenticator、1Password 等）扫码；
2. 填入 App 显示的 6 位数字，点「确认开启」。

以后登录除了密码还要这 6 位数字。同一页能看到最近登录记录，也能「退出其它所有设备」。没有备用恢复码，手机丢了怎么办见[常见问题](#忘了管理员密码--丢了两步验证的手机)。

---

## 添加使用者

面板「使用者」→ 右上角「添加使用者」。每个人可以设：

- **流量上限**（GB，0 = 不限）和**每月几号重置**（0 = 不重置）；
- **到期方式**：永久、指定日期、从今天起多少天，或**首次使用后开始计时**（适合先发链接、后使用）；
- **同时在线设备上限**（0 = 不限）。超了默认暂停 10 分钟，也可以在设置里改成只提醒；
- **限速**（Mbps，0 = 不限），以及**流量用完后降速**到多少 Mbps（0 = 直接停用；填了就不停用，降速用到下次重置或加流量）；
- **可用服务器**：有多台服务器时，可以只让他用其中几台（默认全部，以后新加的也算）；
- 备注。

邀请码也能设限速、降速和可用服务器；会员自己发的码，跟着他本人的设置走。

限速靠内核的流量控制（tc），一般的 KVM / 独立服务器都支持；容器 VPS（OpenVZ、LXC）不支持，面板会提示，限速账号照常全速使用。被限速的账号订阅里不出现 Hysteria 2 节点（它没法按账号限速），Reality / TUIC 照常。升级照常用安装命令（见下面「升级与回滚」），它会顺便给代理服务加上限速需要的权限。

建好后点他的名字，「订阅」里有链接和二维码：发给他，手机扫码，或在 App 里「从 URL 导入」。链接就是钥匙，泄露了点「更换链接」，旧链接立刻失效。

人多的时候：「批量添加」一次最多 200 个（名字自动编号）；列表能搜索、按状态筛选（在线 / 正常 / 已停用 / 7 天内到期 / 快用完）、排序；勾选多人一次性启用、停用、延期、加流量、清零、换链接、删除；「导出表格」得到 CSV，Excel 直接打开。

### 邀请码

面板「会员与邀请」→「生成邀请码」。可以设每个账号的流量、账号有效期、每月重置日、这个码能用几次、几天内有效。管理员发的码不扣任何人的流量。

点「复制注册链接」发给朋友。他打开链接，填邀请码、起个名字、设个密码，马上就有自己的账号。没用完的码可以「撤销」。

### 会员自助（会员中心）

每个使用者都有自己的页面，两种打开方式：

- 用浏览器直接打开他的订阅链接；
- 打开「会员中心地址」（在「会员与邀请」页，默认开启），用名字 + 密码登录。密码由你在他的抽屉里「设置 / 重置密码」，或者他用邀请码注册时自己设。

页面上能看到：剩余流量、到期日、30 天用量、在线设备、一键导入按钮和二维码、该装哪个 App。还能：

- **申请增加流量**：你在「会员与邀请」页批准或拒绝，批准后被停用的账号自动恢复；
- **邀请朋友**：从自己的额度里分一份（自己至少留 1 GB；不限量的账号不能分）；
- 改密码、更换自己的订阅链接。

「会员与邀请」页可以关掉会员邀请或流量申请，也可以写一条公告，显示在每个会员页面顶部。

---

## 各平台怎么连

同一个订阅链接，服务器按 App 自动给出合适的格式。

| 设备 | 推荐 App | 说明 |
|---|---|---|
| Windows | **vps2vpn 客户端** | 到 [vps2vpn-client Releases](https://github.com/xydadada/vps2vpn-client/releases/latest) 下载 `vps2vpn-<版本>-windows-amd64-setup.exe`（安装版）或 `-portable.zip`（免安装）。基于开源的 FlClash，界面更简单，能显示剩余流量、到期时间和 AI 可用性。 |
| Windows / macOS | Clash Verge Rev、FlClash、Mihomo Party | 拿到 Clash（mihomo / Clash Meta）配置，带分流规则。 |
| Android | FlClash、Clash Meta for Android、Hiddify | FlClash / Clash Meta 拿 Clash 配置，Hiddify 拿 sing-box 配置，都带分流规则。 |
| iPhone / iPad | Shadowrocket 小火箭（付费）、Stash、Karing | 小火箭用会员页上的「小火箭（完整配置：节点+分流+DNS）」按钮导入；Stash 拿 Clash 配置，Karing 拿 sing-box 配置。 |
| 各平台 | sing-box 官方 App | 拿 sing-box 配置，带分流规则。 |
| 各平台 | v2rayN、v2rayNG、NekoBox、Happ、Streisand、V2Box 等 | 拿通用分享链接（vless:// hysteria2:// tuic://）。**只有节点，没有本项目的分流规则**，分流按 App 自己的设置。 |

导入后打开 App 里的「系统代理」或「VPN / TUN 模式」开关就行。订阅默认每 12 小时自动更新一次（「协议与设置」里可改成 1–168 小时）。

App 认错了格式？在订阅链接后面加 `?format=clash`、`?format=singbox`、`?format=shadowrocket` 或 `?format=links` 强制指定。

---

## 升级与回滚

**升级**：在服务器上（root）重新运行安装命令就行，用户和设置都保留：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/xydadada/vps2vpn/main/install.sh)
```

- 只会装更新的正式版，不会悄悄降级（确实要降级：`V2V_ALLOW_DOWNGRADE=1 bash install.sh`）。
- 升级前先把数据库和旧版本代码存一份快照，放在 `/var/lib/vps2vpn/upgrade-snapshots/`，保留最近 3 份，并打印回滚命令。
- 新版本起不来时自动换回旧版本。

**回滚**（root）：

```bash
ls /var/lib/vps2vpn/upgrade-snapshots/                               # 看有哪些快照（名字 = UTC 时间 + 升级前的版本）
bash /var/lib/vps2vpn/upgrade-snapshots/<快照名>/restore.sh          # 回到那一份
bash "$(ls -d /var/lib/vps2vpn/upgrade-snapshots/*-v*/ | tail -1)restore.sh"   # 撤销最近一次升级
```

回滚会把数据库也退回快照时的样子：快照之后新加的使用者、用掉的流量都会回到那时。

**换服务器 / 整台丢了**：面板「体检与维护」→「下载备份」得到一个 JSON 文件，在新服务器装好后「从备份恢复」。服务器每天自动备份到 `/var/lib/vps2vpn/backups`（保留 14 天）；连了 Telegram 的话，每天的备份也会发给你。备份里有密钥，自己收好。

---

## 多台服务器

多台服务器可以合成一个订阅：大家的订阅里每台一组节点，自动切换；账号只在主服务器管理，流量算在同一个额度里。

- **用一键部署**：部署第二台时，在「这台服务器怎么用」里选「加到 某某 下面」，全自动。前提是第一台也是在这台电脑上用部署工具装的（保存了它的面板密码）。原来的订阅里自动多出这台，不用重新导入。
- **手动**：
  1. 新服务器装好、走完设置向导；
  2. 在新服务器面板的「多服务器」页复制「本机加入码」；
  3. 回到主服务器面板的「多服务器」页，粘贴加入码，起个显示名字（如「东京」），点「添加服务器」。

加入码相当于那台服务器的钥匙，别发给别人。泄露了在那台上点「换一个加入码」，再到主服务器删掉它重新添加。

**流量倍率**：每台服务器可以设倍率（机场常见做法），比如东京 ×2 表示在东京用 1 GB 记 2 GB，×0.5 记一半，0 表示不计。订阅里的节点组名会带上「×2」。主服务器自己的倍率也在这一页设。

「多服务器」页还能设本机每月流量上限（到 80% / 100% 时 Telegram 提醒，不会自动断网）和 VPS 续费日（到期前 7 天、3 天、1 天和当天提醒）。

---

## Telegram 机器人

可选。连上后，出事会发消息给你，还能在 Telegram 里查状态。

**配对**（面板「体检与维护」→「Telegram 告警」）：

1. 在 Telegram 找 @BotFather，发 `/newbot` 建一个机器人，把它给的 token 贴到面板里；
2. 面板会显示一行 `/bind <配对码>` 命令，把这整行发到**你和机器人的私聊**（不要发到群组）；
3. 点「连接」。

只有发了这条配对命令的私聊会收到告警，机器人也只回复你本人。从 0.2.5 以前的版本升级上来、或从备份恢复后，要重新发一次 `/bind`，之前告警和备份会暂停（面板会提示）。

**会提醒你的事**：有人流量用到 80%、有人 3 天后和明天到期、有人被停用、服务挂了、公网 IP 变了、证书续不上、服务器月流量到 80% / 100%、VPS 快到续费日、AI 可用性变了、几个使用者报告某条线路连不上、风控发现可疑用法（只提醒，不自动封）。

**命令**（在私聊里发给机器人；面板里可以关掉「接受机器人命令」）：

| 命令 | 作用 |
|---|---|
| `/status` | 服务器状态 |
| `/users` | 每人用量 |
| `/user 名字` | 某个人的详情 |
| `/expiring` | 7 天内到期或流量用了 80% 的账号 |
| `/doctor` | 一键体检，只列出有问题的项 |
| `/ai` | AI 可用性检测 |
| `/backup` | 立即发一份备份 |

---

## 常见问题

### 打不开面板

1. 链接要完整，包括端口和随机路径。忘了就在服务器上运行 `vps2vpn info`。
2. 云厂商防火墙放行了面板的 TCP 端口没有？（见[第 2 步](#第-2-步在云厂商的防火墙放行端口)）
3. 浏览器提示不安全：自签名证书，点「高级 → 继续访问」。

### 连不上 / 端口被墙

按顺序排查：

1. 面板「体检与维护」→「开始体检」，或在服务器上运行 `vps2vpn doctor`。每一项不正常都会写怎么修。
2. 核对云厂商防火墙：`vps2vpn info` 列出的每个端口都要放行，注意 TCP 和 UDP 是分开的。
3. 在 App 里换个协议试试。晚高峰 UDP 常被限速，这时 VLESS + REALITY（TCP）更稳；反过来 TCP 卡时试 Hysteria 2。
4. 某个端口被运营商封了：在「协议与设置」或总览页的提醒里点「换一个端口」，换到新的随机端口。然后在云厂商防火墙放行新端口，让大家更新一下订阅。
5. UDP 整个被封时，可以在「协议与设置」里给 Hysteria 2 设一个混淆密码。
6. 服务器的公网 IP 变了：会自动发现，两次确认后把订阅改成新 IP，App 下次更新订阅就好了。

使用 vps2vpn 客户端时，有两个以上使用者报告同一条线路连不上，总览页会提示，Telegram 也会告诉你。

### 证书

- 默认自动向 Let's Encrypt 申请免费证书，**没有域名也行**（纯 IP 证书，有效期约 6 天，自动续期）。条件是云防火墙放行了 **TCP 80**。
- 申请不下来就用自签名证书，代理照样加密能用；但浏览器会提示不安全，**订阅链接会变成 http://**（体检里会说明）。
- 放行 80 后立即重试：面板「协议与设置」→「立即申请证书」，或服务器上 `vps2vpn cert`。有域名的话填进「域名」。

### 流量怎么算

- 每个使用者的流量 = 上传 + 下载，由代理程序按人统计，每 20 秒记一次。到上限自动停用，每月重置日或你加流量后自动恢复。
- 邀请朋友时分出去的额度会从自己的可用额度里扣掉（面板上显示「实际可用额度」）。
- 多台服务器时，各台的流量都汇总到主服务器同一个额度里；设了倍率的服务器按倍率记。
- 「本机本月流量」是服务器网卡的总流量，和云厂商账单更接近；使用者流量的合计会比它少一些。
- 在面板里可以给某人「清零流量」。

### AI 可用性体检

- 从服务器上直接测 claude.ai 网页、Claude API、ChatGPT、Gemini，结果是「能用 / 地区不支持 / 连不上 / 不确定」，同时显示 IP 在哪个城市、哪家机房、是机房 IP 还是家庭宽带 IP。
- 在面板「体检与维护」点「重新检测」（约 10 秒），或在 Telegram 发 `/ai`。每天自动复查一次，结果变了会提醒。
- 结果只作参考：账号会不会被封，还和付款方式、注册信息、使用习惯有关。

### 忘了管理员密码 / 丢了两步验证的手机

以下命令都在服务器上以 root 运行（先 `sudo -i`）。

- **忘了密码**：

  ```bash
  vps2vpn reset-password                       # 按提示输入新密码（至少 8 位），所有已登录的设备都会退出
  vps2vpn reset-password --username 新用户名    # 顺便改用户名
  ```

  它不会关掉两步验证。

- **丢了验证器手机**：没有备用恢复码，也没有专门的命令。可以用下面这行直接关掉两步验证，立即生效：

  ```bash
  PYTHONPATH=/usr/local/lib/vps2vpn/app python3 -c "from vps2vpn import db; db.set_settings(admin_totp='')"
  ```

  然后用密码登录，在「登录安全」里重新开启。（两步验证保护的是网页登录；能以 root 登录服务器的人本来就能管一切。）

- **会员忘了密码**：在他的抽屉里「设置 / 重置密码」。他也可以直接用订阅链接打开自己的页面。

### Claude Code 等命令行工具不走代理

终端程序不一定读系统代理。先设好再用，例如 PowerShell：`$env:HTTPS_PROXY="http://127.0.0.1:7890"`，macOS / Linux：`export HTTPS_PROXY=http://127.0.0.1:7890`（端口以你的 Clash 软件里显示的为准）。也可以在 App 里打开 TUN 模式，所有程序都会走代理。

---

## 功能一览

**搭建**
- 一键安装脚本：Debian / Ubuntu / RHEL 系 / Fedora / openSUSE / Arch，x86_64 和 arm64。重复运行就是升级，用户和设置都保留。
- 核心程序从官方 GitHub Release 下载，并**逐个校验 SHA-256**。
- 自动挑选伪装网站：从服务器实测一批大网站，选支持 TLS 1.3 + HTTP/2 且最快的那个。
- **免费受信任证书**：自动向 Let's Encrypt 申请，没有域名也行（Let's Encrypt 从 2026 年 1 月起正式支持纯 IP 证书，有效期约 6 天，面板自动续期）。申请失败自动退回自签名证书。
- 只有系统已开着 ufw / firewalld 时才去放行端口；不会擅自打开防火墙把你锁在外面。
- **端口被占用自动避让**：443 已经被 nginx / 其它面板占着，就自动换到别的空闲端口，并告诉你是谁占的。
- 小内存机器（< 1 GB）自动加 1 GB swap，自动开启时间同步（时间不准会导致连不上）。
- 升级前自动快照，升级失败自动回滚到上一个版本。

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
- 国内网站、国内下载（Steam、苹果、微软、游戏 CDN）直连；国外走代理；可选屏蔽广告、禁止 BT 走服务器。
- **DNS 防泄漏**：国外域名的 DNS 查询经代理发往 Cloudflare / Google，运营商看不到你查了什么。
- 订阅头带流量和到期信息，App 里直接显示剩余流量；快到期或快用完（90%）时，支持公告的 App（Happ、Hiddify、Streisand 等）会显示提醒；账号停用时 App 里显示一条写着原因的节点。
- 可设订阅自动更新间隔（1–168 小时，默认 12）和 App 里显示的客服 / 帮助链接。

**AI 专区（用 Claude / ChatGPT / Gemini 的看这里）**
- **AI 可用性体检**：见[常见问题](#ai-可用性体检)。一键部署完成时直接告诉你：**「这台服务器：Claude ✓ ChatGPT ✓ Gemini ✓」**。
- **AI 固定出口**：订阅里的「AI服务」分组专门管 Claude、ChatGPT、Gemini、Grok、Perplexity 这些网站。普通上网可以「自动选最快」，**AI 网站固定走同一台服务器**，不跟着来回跳。有多台服务器时，默认选 AI 体检结果最好的那台，App 里也能自己改。
- 一键部署时服务器自动用所在城市起名（例如「悉尼」），App 里看到的是「悉尼 Hysteria2」而不是一串数字。

> **给 Claude 用户的几句大实话**
> 1. 选服务器：美国、日本、新加坡、英国、澳大利亚等地区都能用 Claude；香港、中国大陆、俄罗斯等地区用不了。部署完看一眼体检结果就知道。
> 2. **固定一个出口**：登录 Claude 时尽量一直用同一台服务器，别今天美国明天日本。这就是上面「AI 固定出口」做的事。
> 3. 机房 IP（所有 VPS 都是）打开 claude.ai 时可能先做一次人机验证，浏览器里一般自动通过，不算被封。
> 4. **Claude Code 等命令行工具**不一定走系统代理，见[常见问题](#claude-code-等命令行工具不走代理)。
> 5. 体检结果只作参考，本项目不承诺「防封」。

**管理面板**
- 一键部署工具自动建好管理员和第一个账号；手动安装时用首次设置向导（安装时生成一次性链接，别人抢不走）。
- 使用者：增删改、暂停、清零流量、更换链接（旧链接立即失效）、批量操作、批量添加、导出 CSV；能看到每人最近一次拉取订阅的时间和 App。
- **设备数上限**、**首次使用才开始计时**、**自定义分流**（自己填「直连 / 走代理 / 屏蔽」的域名清单，Clash、sing-box、小火箭三种订阅一起生效）。
- 概览：实时速度、在线数、内存、负载、30 天流量图、服务状态，服务器 24 小时 CPU / 内存 / 网络曲线（重启也不丢）。
- 备份 / 恢复（一个 JSON 文件），修改管理员密码，查看日志；每天自动备份，保留 14 天。
- **一键体检**：逐项检查服务、伪装网站、证书、BBR、UDP 缓冲、时间同步、IP 是否变了、服务器能否上外网、磁盘内存、规则更新，每一项不正常都直接告诉你怎么修。
- **自动看护**：代理挂了自动拉起；云服务器换了公网 IP，两次确认后自动把订阅改成新 IP。
- **Telegram 告警和命令**：见 [Telegram 机器人](#telegram-机器人)。
- 可选同时提供 **IPv6 节点**：IPv4 线路卡的时候换着用。
- **会员中心、邀请码、申请加流量**：见[添加使用者](#添加使用者)。
- **在线状态**：三种协议都能看到谁在线、几台设备、哪些 IP。
- **网站监控**：每 5 分钟从服务器测 GitHub、YouTube、ChatGPT（含地区是否被封）、Google、X、Telegram 的 IPv4 / IPv6 延迟和测速，保留 24 小时曲线。
- **风控观察**（只提醒、不自动封）：像扫描/当跳板、链接被很多人共用、大量发邮件时记一笔并发 Telegram。
- **服务器月流量**和 **VPS 续费提醒**。
- **多台服务器合成一个订阅**：见[多台服务器](#多台服务器)。
- **vps2vpn 客户端更新**：面板每 6 小时自动从 GitHub 取最新的客户端（带签名的 Windows 安装包和安卓 APK）放进 `/var/lib/vps2vpn/client`，不用手动拷贝（设置 → 客户端更新里可以关掉；也可以自己把安装包连同同名 `.sig` 放进去）。客户端 1.0.9 起会在后台下载、校验签名，点一下「安装并重启」就升级；只接受带正确签名、且版本更新的安装包，所以就算面板被人动了手脚，也换不了安装包。
- 中文 / English，自动深色模式，手机上自动变成底部标签栏。
- **两步验证（2FA）**、**登录记录**和「退出其它所有设备」。
- 安全：PBKDF2 密码哈希、登录限速、HttpOnly + SameSite=Strict 会话、防跨站请求、严格 CSP、面板藏在随机路径下（直接访问端口只看到一个 nginx 404）。

---

## 实测（本项目的测试都是真程序真流量）

`python -m unittest tests.test_unit tests.test_features tests.test_admin tests.test_deploy tests.test_ops tests.test_telegram_pairing tests.test_cluster_sync_http` —— 350 项离线测试：X25519 对照 RFC 7748 标准向量、二维码逐像素对照参考实现、用户限额 / 到期 / 月重置、备份恢复、完整的网页流程（设置向导、登录限速、跨站拦截、订阅格式识别）、邀请码额度计算、会员注册登录与申请审批、小火箭配置、防滥用判定、两台服务器之间真实 HTTPS（证书固定）同步、两步验证（对照 RFC 6238 标准向量）、批量操作、设备上限、自定义分流、Telegram 配对和命令只认主人、到期提醒、一键部署（免向导建账号、保存的密码升级后不丢、从外部测 TCP/UDP 端口、证书固定登录主服务器并加入）、AI 可用性体检（模拟能用 / 地区封锁 / 断网三种情况）、AI 网站在三种订阅里都走「AI服务」分组、AI 体检最好的服务器排第一。

`python tests/e2e_local.py <放官方程序的目录>` —— 在一台电脑上启动**真的** Xray、Hysteria 和 sing-box（TUIC）服务端，再用**真的** mihomo（Clash 内核）和 sing-box 客户端发流量，共 54 项检查：

- 服务端配置被 Xray 自己的校验通过；REALITY 公钥与 `xray x25519` 结果一致
- 完整订阅被 `mihomo -t` 和 `sing-box check` 校验通过（含端口跳跃、混淆）
- mihomo、sing-box 两个客户端 × Hysteria 2、REALITY、TUIC 三种协议，六条路全部真实上网成功；TUIC 流量能准确记到对应使用者头上
- 每个用户的流量被正确计数；错误密码被拒绝
- 测速工具 `tools/bench.py` 能通过两个协议分别跑完
- 连接保持期间，三种协议都能正确识别在线用户和设备；防滥用扫描能读到流向；小火箭规则转换和配置生成；网站监控探测

**测试中发现的一个上游兼容问题**：Xray **v26.10.21 及更新版本**的 REALITY 服务端会拒绝 mihomo 1.19.34 和 sing-box 1.14.4 客户端的登录（Xray 自己的客户端不受影响）。v26.3.27 三种客户端全部正常。因为大多数人用的是 Clash 类 App 和小火箭，安装脚本**固定使用 Xray v26.3.27**，等上游修复后再升级。

**测速**（本项目不编造数字，你可以自己测）：

```bash
vps2vpn bench                                   # 在服务器上：服务器本身到外网的速度（VPN 不可能比它更快）
python tools/bench.py "你的订阅链接" --mihomo <mihomo程序路径>   # 在你电脑上：直连 vs 每个协议
```

电脑端会临时启动一个只监听本机的 mihomo，逐个协议测：延迟（每次都是全新 HTTPS 握手，中位数和 p90）、单连接下载、4 连接下载、上传，并和直连对比，`--json 文件名` 可以存结果。不会改你电脑上的任何代理设置。

---

## 命令行（服务器上）

都要 root（先 `sudo -i`）。

```bash
vps2vpn info              # 再次显示面板链接、证书状态、需要放行的端口
vps2vpn reset-password    # 忘了管理员密码（--username 可同时改用户名）
vps2vpn apply --force     # 重新生成配置并重启代理
vps2vpn cert              # 立即申请 / 续期证书
vps2vpn rules             # 立即更新分流规则镜像
vps2vpn sysctl            # 看本机会被设成什么内核参数
vps2vpn doctor            # 一键体检（和面板里的一样），--json 输出机器可读结果
vps2vpn bench             # 测服务器本身的网速（--quick 测得短一些）
vps2vpn backup            # 立即备份一次（自动备份在 /var/lib/vps2vpn/backups）
```

卸载（保留数据；最后加 `--purge` 连数据一起删）：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/xydadada/vps2vpn/main/install.sh) uninstall
```

（有代码目录的话：`bash install.sh uninstall`。）

文件位置：配置和密钥 `/etc/vps2vpn`，数据库、规则镜像、备份和升级快照 `/var/lib/vps2vpn`，程序 `/usr/local/lib/vps2vpn`，内核参数 `/etc/sysctl.d/99-vps2vpn.conf`。

## 开发

```bash
python -m unittest tests.test_unit tests.test_features tests.test_admin tests.test_deploy tests.test_ops tests.test_telegram_pairing tests.test_cluster_sync_http -v   # 离线测试
python tests/dev_server.py 8443           # 本机跑面板（开发模式，不动系统）
python tests/e2e_local.py ./bins          # 真程序端到端测试
sudo bash tests/vps_acceptance.sh --full  # 在一台可以随便折腾的真 VPS 上做验收（含重装、卸载再装）
V2V_REF=main bash install.sh              # 装开发分支（不校验，只用于测试）
```

`.github/workflows/test.yml` 在 GitHub 上自动跑：Python 3.8 / 3.12 单元测试、shellcheck 和部署器检查、Linux 上的真程序端到端测试，以及在全新 Ubuntu 上真正运行安装脚本再跑验收。

面板只用 Python 标准库；前端是不依赖框架的原生 JavaScript。

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

**vps2vpn** turns a fresh Linux VPS into a private VPN server with a web panel, for people who know nothing about networking and want to share it with family and friends.

### Quick start

1. **Server**: Ubuntu 22.04/24.04 or Debian 12 is easiest (RHEL family, Fedora, openSUSE and Arch work too), x86_64 or arm64, 512 MB RAM is enough. For Claude/ChatGPT pick the US, Japan, Singapore, the UK or Australia; Hong Kong does not work for them.
2. **Open these ports in your provider's firewall**: the panel's TCP port (random, 40001–60000, shown at install), TCP 80 (certificates), TCP 443 (REALITY), UDP 443 and UDP 20000-40000 (Hysteria 2), UDP 8443 (TUIC). `vps2vpn info` prints the exact list.
3. **Install** – pick one:
   - *From your computer:* download the repo (Releases → Source code (zip)) and double-click `deploy-windows.bat` (Windows 10/11, nothing to install) or `deploy-mac.command` (macOS/Linux). Type the server IP, drag in the SSH key file (or the whole `.ssh` folder, or type the root password), click **Deploy**. It creates the admin and the first user, tests the ports from outside and imports the profile into your VPN app.
   - *On the server, as root (`sudo -i` first):* `bash <(curl -fsSL https://raw.githubusercontent.com/xydadada/vps2vpn/main/install.sh)`
   - *From a checkout:* `sudo bash install.sh`
4. **First login**: open the full link it prints (`https://<server-ip>:<port>/<random path>/?setup=...`; lost it: `vps2vpn info`), accept the self-signed certificate warning, set an admin password, click **Build my VPN**, scan the QR code.
5. **Turn on 2FA**: Health & upkeep → Sign-in security. There are no recovery codes (see below).

### Users, invites, member page

Add users with a quota, an expiry (date, days, or counting from first use), a monthly reset day, a device limit, a speed limit, a slow-down speed once the quota is used up (instead of stopping the account) and the servers they may use. Speed limits use the kernel's tc (not on OpenVZ/LXC containers); a limited account gets no Hysteria 2 entries. Each user gets one link and QR code. Admin invite codes create accounts with preset limits; members can carve invite codes from their own quota (keeping at least 1 GB). Opening the subscription link in a browser (or logging in at the member-centre address) shows the member page: remaining data, import buttons, quota requests, invites, password and link change.

### Apps

| Device | App | Gets |
|---|---|---|
| Windows | **vps2vpn client** ([vps2vpn-client releases](https://github.com/xydadada/vps2vpn-client/releases/latest), `-windows-amd64-setup.exe` or `-portable.zip`) | Clash config |
| Windows / macOS | Clash Verge Rev, FlClash, Mihomo Party | Clash (mihomo) config with rules |
| Android | FlClash, Clash Meta for Android, Hiddify | Clash or sing-box config with rules |
| iPhone / iPad | Shadowrocket (full config button), Stash, Karing | native Shadowrocket, Clash or sing-box config |
| any | sing-box | sing-box config with rules |
| any | v2rayN, v2rayNG, NekoBox, Happ, Streisand, V2Box… | share links only (no routing rules) |

Force a format with `?format=clash|singbox|shadowrocket|links`. Apps refresh every 12 hours by default (1–168, in Protocols & settings).

### Upgrade and roll back

Re-run the one-line installer as root. It installs the latest tagged release, checks its SHA256, never downgrades silently (`V2V_ALLOW_DOWNGRADE=1` to force), snapshots the database and code to `/var/lib/vps2vpn/upgrade-snapshots/` (last 3 kept) and puts the old version back if the new one fails to start. Roll back: `bash /var/lib/vps2vpn/upgrade-snapshots/<snapshot>/restore.sh` (the database goes back too). Moving servers: download a backup in the panel and restore it on the new one; daily backups are in `/var/lib/vps2vpn/backups` (14 days) and, with Telegram, sent to you.

### Several servers

Deployer (Chinese UI): under 这台服务器怎么用 pick 加到 <first server> 下面 (needs the first server deployed from the same computer, so its panel password is saved). By hand: copy the join code from the new server's Servers page and paste it on the main server's Servers page. Users are managed on the main server only; every subscription gets each server's entries and traffic counts against the same quota. Each server can have a traffic rate (x2 counts 1 GB as 2 GB), shown in the group names.

### Telegram bot

Health & upkeep → Telegram alerts: create a bot with @BotFather, paste the token, send the shown `/bind <code>` line to the bot in a private chat, press Connect. Alerts: 80% quota, accounts ending in 3 days and tomorrow, paused accounts, services down, IP change, certificate renewal failing, server monthly cap, VPS renewal, AI availability changes, line reports, abuse signals. Commands: `/status`, `/users`, `/user NAME`, `/expiring`, `/doctor`, `/ai`, `/backup`. Bindings from before 0.2.5 or from a restored backup need one fresh `/bind`.

### Troubleshooting

- *Cannot connect*: run the health check (panel or `vps2vpn doctor`), check every port in the cloud firewall (TCP and UDP separately), try the other protocol in the app, use "Use another port" for a blocked port (then open it in the cloud firewall and refresh subscriptions), or set a Hysteria 2 obfuscation password when UDP is blocked.
- *Certificate*: Let's Encrypt works without a domain (IP certificates, ~6 days, renewed automatically) once TCP 80 is open; retry with `vps2vpn cert`. With the self-signed fallback the browser warns and subscription links use plain HTTP.
- *Traffic*: upload + download per user, counted by the proxy cores every 20 s; joined servers report into the same quota. The server's monthly figure is the network card total and is closer to the provider's bill.
- *AI check*: tests claude.ai, the Claude API, ChatGPT and Gemini from the server (panel, Telegram `/ai`, daily). A hint, not a promise about account bans.
- *Forgot the admin password*: `vps2vpn reset-password` (as root; `--username` also renames; signs out every session; leaves 2FA on).
- *Lost the 2FA phone*: there is no recovery code or command. As root: `PYTHONPATH=/usr/local/lib/vps2vpn/app python3 -c "from vps2vpn import db; db.set_settings(admin_totp='')"`, then log in with the password and enrol again.

### Tested

365 offline tests, `tests/e2e_local.py` with real Xray/Hysteria/sing-box servers and real mihomo/sing-box clients (54 checks), and `tests/vps_acceptance.sh` on a real server. Xray is pinned to **v26.3.27** because v26.10.21+ rejects REALITY logins from mihomo 1.19.34 and sing-box 1.14.4.

Standard-library Python panel: no Docker, no database server, no third-party scripts in the browser.

Please follow the laws that apply to you and to your server's location.
