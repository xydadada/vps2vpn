# 第二阶段服务端接口设计：一键反馈、设备管理、节点状态

状态：**只是设计，还没写代码**（2026-11-24）。需求来自客户端仓库 `ROADMAP.md` 第六节第 2、3、4 条。
字段名定了以后，客户端会话把它们写回 `ROADMAP.md`。这里改了，也要同步过去。

这个仓库是公开的：文档、代码、测试里的示例地址只用 192.0.2.x、198.51.100.x、203.0.113.x、2001:db8::。

## 0. 共同约定

### 路径和鉴权

三组接口都挂在现有的会员接口下面，和 `api/me` 用同一套鉴权、同一个处理函数（`web.py` 里的 `member_area`）：

| 入口 | 谁用 | 凭据 |
|---|---|---|
| `https://<面板地址>/s/<订阅 token>/api/<名字>` | 客户端（用订阅链接） | 链接里的 token 就是凭据 |
| `https://<面板地址>/<member_path>/api/<名字>` | 会员中心网页 | 登录后的 `v2vm` cookie |

- 只走 HTTPS：现在这两个入口在不安全的连接上分别返回 426 和跳转到 HTTPS（`secure_ok`），新接口照旧。
- token 轮换（`api/rotate`）以后旧链接返回 404，新接口也一样。
- 账号停用、暂停时 `api/me` 照样能看，新接口也照样能用。尤其是反馈：「连不上」的时候最需要它。只有被删掉的账号是 404。
- 写操作只接受 `POST`，请求体是 JSON（`Content-Type: application/json`）。`GET` 用来读。
- 客户端用的订阅链接都来自主服务器，所以这些接口只在主服务器上用到，子服务器不另做。

### 返回格式和错误码

成功时返回 `200` 和 JSON 对象。出错时沿用现在的写法 `{"error": "<英文句子>"}`：会员网页的 `kit.js` 会把它翻成中文。
新接口在出错时**多带一个机器读的 `code`**，客户端按 `code` 判断，不要去解析英文句子：

| HTTP | `code` | 什么时候 |
|---|---|---|
| 400 | `bad_request` | JSON 坏了、缺字段、类型不对、超出长度 |
| 401 | `login_required` | 会员中心没登录（只有 cookie 入口会出现） |
| 403 | `not_allowed` | 这个账号不允许做这件事（例如管理员关掉了反馈） |
| 404 | `not_found` | 链接不对、token 已轮换、设备 id 不存在 |
| 405 | `post_only` | 写操作用了 GET |
| 413 | `too_large` | 请求体超过上限 |
| 429 | `rate_limited` | 太频繁。同时返回 `Retry-After`（秒） |
| 503 | `feature_off` | 管理员没打开这个功能 |

### 功能开关

三个功能都要管理员先打开，默认全关。和流量排行一样，开关状态在 `api/me` 的 `features` 里告诉客户端：

```json
"features": {"traffic_rank": false, "feedback": true, "devices": true, "node_status": true}
```

- 读不到某个键，就当它是 `false`。老面板不会有这些键，老客户端也会忽略它们。
- 设置项名字：`client_feedback`、`client_devices`、`client_node_status`，都是布尔值，默认 `false`。在面板「vps2vpn 客户端更新」那一块，放在流量排行开关旁边。

## 1. 一键反馈

### 1.1 接口

`POST <sub>/api/feedback`

```json
{
  "text": "下午 3 点开始 YouTube 打不开",
  "diagnosis": {"steps": [{"id": "dns", "ok": false, "detail": "..."}]},
  "log": "已经打码的最近日志，纯文本",
  "client": {"version": "1.0.29", "platform": "windows", "os": "Windows 11 23H2", "core": "mihomo 1.19.x"},
  "device_id": "3f2c9a1e-...（见 2.1，可以不带）"
}
```

| 字段 | 必填 | 限制 |
|---|---|---|
| `text` | 否 | 用户自己写的话，最多 1000 个字符，去掉控制字符（换行保留） |
| `diagnosis` | 否 | 网络诊断向导（`diagnose.dart`）和体检的结果，JSON 对象，序列化后最多 32 KB |
| `log` | 否 | 最多 64 KB，UTF-8 纯文本 |
| `client` | 是 | 每个值是字符串，最多 64 个字符；`platform` 只能是 `windows` / `android` / `macos` / `linux` / `ios` |
| `device_id` | 否 | 格式同第 2 节 |

- `text`、`diagnosis`、`log` 至少要有一个。整个请求体最多 128 KB，超过就返回 413。
- 成功：`200 {"ok": true, "id": 123}`。

### 1.2 频率和存储上限

- 每个账号：2 分钟内最多 1 条，24 小时内最多 5 条。超过就返回 429 和 `Retry-After`。
- 每个账号最多保留最近 20 条，整台面板最多 500 条，超过就删最旧的。
- 保留 30 天。每天的维护任务（`jobs.py` 里每天跑的那一段）删掉 30 天前的反馈，已处理的、没处理的都删。
- **不进备份**：`export_all` 不导出反馈表。恢复备份也不会带回旧反馈。

### 1.3 隐私（客户端先打码，服务端再兜底）

客户端在发送前必须打码。规则写进客户端，发送前给用户看一眼「将要发送的内容」，用户确认才发：
- IPv4、IPv6 地址：保留前两段，其余换成 `x`，例如 `203.0.x.x`、`2001:db8:x:x:...`；
- 订阅链接和其中的 token、节点 UUID、各协议密码：整段换成 `<hidden>`；
- 本机用户名、主机名、Wi-Fi 名称：换成 `<hidden>`。

服务端收到后**再扫一遍**，不能只信客户端：
- 遇到这个账号自己的 `sub_token`、`uuid`、`hy2_pass`，原样换成 `<hidden>`；
- 遇到完整的 IPv4 / IPv6 地址，用同样的规则打码。面板自己的公网地址也一样打码：管理员本来就知道它。
- 打码在**写入数据库之前**做，数据库里不存原文。

### 1.4 数据表

```sql
CREATE TABLE IF NOT EXISTS feedback (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  device_id TEXT NOT NULL DEFAULT '',
  client TEXT NOT NULL DEFAULT '{}',      -- JSON
  text TEXT NOT NULL DEFAULT '',
  diagnosis TEXT NOT NULL DEFAULT '{}',   -- JSON
  log TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'open',    -- open / done
  answer TEXT NOT NULL DEFAULT '',        -- 管理员的回复，最多 500 字
  answered_at INTEGER NOT NULL DEFAULT 0
);
```

账号被删掉时，它的反馈一起删。

### 1.5 管理面板

- 侧边栏「会员」下加「反馈」页。待处理的数目用红点标在菜单上（和「流量申请」一样）。
- 列表：时间、账号名、客户端版本和平台、用户写的话的前 80 个字、状态。
- 点开看详情：诊断结果按步骤显示（绿 / 红），日志放在可折叠、可复制的等宽框里。
- 操作：「回复并标为已处理」（填一句话）、「标为已处理」、「删除」。
- 收到新反馈时，如果配了 Telegram，就发一条提醒：「<账号> 发来反馈：<前 50 字>」，同一账号 1 小时最多一条。

### 1.6 用户看到回复

`GET <sub>/api/feedback` 返回这个账号最近 10 条反馈的摘要（不含日志）：

```json
{"items": [{"id": 123, "created_at": 1795000000, "text": "前 200 字", "status": "done",
            "answer": "已经换了线路，再试一下", "answered_at": 1795003600}]}
```

客户端「反馈」页显示这些；`api/me` 里多一个 `feedback_unread`（有新回复的条数），客户端据此提示。

## 2. 设备管理

### 2.1 设备从哪里来：客户端自报

现在服务端只知道「同时有几个 IP 在连」（`cores.online_detail`：Xray 和 TUIC 报客户端地址，Hysteria 只报数量）。
同一个 IP 背后可能有几台设备（家里共用一个出口）；一台手机换网络，IP 也会变。所以靠 IP 认不出「设备」。

做法：客户端第一次运行时生成一个随机 UUID 作为 `device_id`，存在本机。之后每次连上和每 30 分钟，向面板报一次：

`POST <sub>/api/device`

```json
{"device_id": "3f2c9a1e-7b1d-4c3e-9a55-0d1e2f3a4b5c", "name": "小明的 Pixel 8",
 "platform": "android", "version": "1.0.29"}
```

| 字段 | 限制 |
|---|---|
| `device_id` | 必填，小写 UUID 格式（8-4-4-4-12） |
| `name` | 最多 40 个字符，去掉控制字符；客户端默认用系统里的设备名，用户可以改 |
| `platform` | 同 1.1 |
| `version` | 最多 32 个字符 |

- 返回 `200 {"ok": true, "revoked": false}`。已经被踢下线的设备返回 `{"ok": true, "revoked": true}`，见 2.3。
- 服务端记下：第一次出现时间、最后一次报到时间、最后一次报到的 IP（打码后存，规则同 1.3）。
- 频率：同一设备 1 分钟内最多 1 次，超过返回 429，客户端可以忽略。每个账号最多记 50 台，超过就把最久没报到的那台挤掉。
- **只有我们自己的客户端会报到。** 用 Clash Verge、Shadowrocket 之类第三方软件导入订阅的设备不会出现在列表里，界面上要写明。

### 2.2 看设备列表

`GET <sub>/api/devices`

```json
{
  "devices": [
    {"device_id": "3f2c...", "name": "小明的 Pixel 8", "platform": "android", "version": "1.0.29",
     "first_seen": 1795000000, "last_seen": 1795003600, "ip": "198.51.x.x",
     "this_device": true, "revoked": false}
  ],
  "online_ips": 2,
  "max_ips": 3
}
```

- `this_device`：请求里带了请求头 `X-V2V-Device: <device_id>` 时，标出是哪一台。
- `online_ips` 和 `max_ips` 来自现有的设备数限制，让用户对照「我登记了几台，实际有几个地址在连」。

### 2.3 踢下线

现在一个账号所有设备共用同一套协议凭据（同一个 UUID、同一个 Hysteria 密码）。服务端**没办法只让其中一台连不上**，除非给每台设备单独发凭据（见 2.5）。所以分两种：

1. **踢掉一台（软踢）**：`POST <sub>/api/devices/<device_id>/revoke`
   - 服务端把这台标为 `revoked`。它下次报到时拿到 `"revoked": true`，**我们的客户端**就断开连接、删掉本机保存的这个订阅，并提示「这台设备已被账号主人移除」。
   - 对第三方软件和改过的客户端没用，界面上要写明「只对 vps2vpn 客户端有效」。
   - 被踢的设备以后再报到，仍返回 `revoked: true`。用户在列表里点「恢复」（`POST .../unrevoke`）才能再用。
2. **踢掉所有别的设备（硬踢）**：`POST <sub>/api/devices/kick-others`
   - 就是现有的「换订阅链接」：新的 `sub_token`、`uuid`、`hy2_pass`，所有旧连接 1 分钟内失效（核心重新加载）。
   - 返回新的订阅链接 `{"ok": true, "sub_url": "https://.../s/<新 token>"}`。发起请求的这台客户端直接换上新链接，其他设备都要重新导入。
   - 频率：每个账号 1 小时最多 3 次。
   - 管理员面板里对每个账号也有同样的按钮。

### 2.4 和现有设备数限制（`max_ips`）怎么配合

- 现有的限制**不变**：`jobs.device_limits` 继续按核心报的在线 IP 数判断，超了就按设置提醒或暂停 10 分钟。设备是客户端自报的，可以造假，所以不能用来执行限制。
- 设备列表只是让用户和管理员**看清楚**是谁在用。
- 超限的提醒（Telegram、事件记录）里，附上最近 1 小时报到过的设备名，方便管理员判断。

### 2.5 以后可以做的：每台设备单独的凭据（不在这一版）

Xray 和 sing-box 都支持一个入口下有多个用户。如果每台登记的设备有自己的 UUID 和密码，就能真正只踢一台。
代价是：流量统计要按设备汇总回账号，订阅要按设备生成，第三方软件导入时也要先「登记一台设备」。改动大，等用户确认需要再做。

### 2.6 数据表

```sql
CREATE TABLE IF NOT EXISTS devices (
  user_id INTEGER NOT NULL,
  device_id TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  platform TEXT NOT NULL DEFAULT '',
  version TEXT NOT NULL DEFAULT '',
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  ip TEXT NOT NULL DEFAULT '',            -- 已打码
  revoked INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, device_id)
);
```

- 90 天没报到的设备自动删掉（每天的维护任务）。账号删掉时一起删。
- 换订阅链接（硬踢）时，除发起请求的这台外，其余设备行都删掉。
- 不进备份。

### 2.7 管理面板

- 用户编辑窗口里加「设备」一栏：设备列表（名字、平台、版本、最后在线、打码 IP、是否已踢）、「踢下线」「恢复」「换订阅链接」。
- 用户列表的「在线」那一列不变（仍是核心报的 IP 数）。

## 3. 节点状态下发

### 3.1 管理员怎么标

- 主服务器自己和每台子服务器，各有一个状态：
  - `ok`：正常，默认；
  - `maintenance`：维护中；
  - `congested`：拥堵。
- 可以附一句话（最多 100 个字符）和一个结束时间（可不填）。到了结束时间自动回到 `ok`。
- 存在设置里：主服务器用 `node_status`（对象），子服务器写在 `servers[]` 每一项的 `status` 里。格式相同：

```json
{"state": "maintenance", "note": "今晚 23:00–23:30 换机房", "until": 1795012200}
```

- 面板「服务器」页每台服务器的卡片上加一个状态下拉框、备注框和结束时间。保存后马上生效，不用重启核心。

### 3.2 客户端怎么拿到

放进 `api/me`，客户端本来就会定期读它，不加新接口：

```json
"nodes": [
  {"id": "main", "group": "Tokyo", "names": ["Tokyo Reality", "Tokyo Hysteria2", "Tokyo TUIC"],
   "state": "ok", "note": "", "until": 0},
  {"id": "a1b2c3d4", "group": "Osaka ×2", "names": ["Osaka ×2 Reality"],
   "state": "maintenance", "note": "今晚 23:00–23:30 换机房", "until": 1795012200}
]
```

- 只列这个账号能用的服务器（`db.allowed_on`），顺序和订阅一致。
- `group` 是订阅里这台服务器那一组的名字，`names` 是这一组里每个节点的名字，都和订阅里一字不差（由 `subscription.server_groups` 生成）。客户端按名字把状态对到节点列表上，不用自己猜。
- `features.node_status` 为 `false` 时不返回 `nodes`（或者返回空列表），客户端不显示任何状态。
- 客户端显示：维护中标灰并写备注；拥堵标黄。**自动选线路时跳过 `maintenance` 的节点**，`congested` 的只排到后面。用户手动选的照样能连。

### 3.3 订阅本身要不要变

不变。状态只经 `api/me` 下发，订阅文件里的节点名和顺序都不动。这样第三方软件不受影响，订阅也不会因为改状态而变化、触发客户端重新下载。

## 4. 实现顺序（建议）

1. 节点状态：只加设置和 `api/me` 字段，改动最小。
2. 一键反馈：新表、两个接口、面板页、每天清理。
3. 设备管理：新表、报到和列表接口、软踢和硬踢、面板里的设备栏。

每一项都要有离线测试：鉴权（错误 token 返回 404、cookie 入口要登录）、`code` 字段、频率限制、长度上限、服务端打码、过期清理、不进备份。
