# Changelog

## 0.2.1

- Fixed: with the same line failing on several servers, one server recovering cleared the others' reports; reports are now kept per account and server (alerts still count each account once). At most 64 servers per account and line.
- The member API (`/s/<token>/api/me`, `/api/report`) answers a plain-http request carrying a valid token with 426 "https_required", so the app no longer mistakes an http subscription link for a changed link. Wrong tokens still get the ordinary 404.

## 0.2.0

**AI zone (for Claude / ChatGPT / Gemini users)**
- AI availability check, run from the server: claude.ai, the Claude API, ChatGPT and Gemini, each reported as works / region blocked / unreachable, plus the address's city, network owner and type (data centre, home broadband, mobile). Implemented in Python (`vps2vpn/aicheck.py`); no third-party scripts are run.
- The deployers show the result when they finish ("Claude ✓  ChatGPT ✓  Gemini ✓"); the panel has an "AI availability" card with "check again"; Telegram `/ai`.
- Checked again daily; a change (for example Claude stops working from this server) is sent to Telegram.
- Subscriptions route Claude / Anthropic, OpenAI, Gemini / AI Studio, Grok and Perplexity domains to the "AI" group ahead of everything else. With several servers, the AI group starts on the server with the best AI result, so AI traffic stays on one address instead of following "Auto".
- A one-click deploy names the server after its city ("悉尼"), so app entries read "悉尼 Hysteria2". A second server joins the first under that name.
- README: notes for Claude users (choosing a region, keeping one exit, Claude Code behind a proxy).
- The Mac deployer (also without Python) shows the AI result too.
- Fixed: two servers in the same city both got the same name, which made Clash reject the subscription; the second is now "悉尼 2" (also when renaming in the panel).
- README: "before you buy a server" (system, region for speed vs. for AI, traffic, key file, firewall).
- The panel accepts request bodies sent in chunks (Transfer-Encoding: chunked), as the Dart client sends them.
- Verified from zero: two fresh Ubuntu 24.04 machines deployed with the one-click tool, the second joined to the first automatically; all ports, the AI check, the health check and the merged subscription were correct.

**Truly one click**
- The deployers (Windows window, browser page, Mac/Linux) finish the setup themselves: the admin login and the first account are created on the server (`vps2vpn init --auto`, `V2V_AUTO=1`), no setup link to open.
- They find the VPN app on the computer (Clash Verge, FlClash, Mihomo Party, Clash Nyanpasu, Hiddify...) from the registered `clash://` link handler and open it with the subscription; without one they link to the Clash Verge Rev download. A QR code covers phones.
- Firewall check from the owner's computer: TCP connect to the panel and REALITY ports, and a QUIC version-negotiation probe for Hysteria 2 and TUIC (proves UDP gets through). Blocked ports come with the cloud's own instructions and a "check again" button.
- Each server's login is saved only on that computer (`~/vps2vpn/<server>.json`, private to the user); an upgrade keeps the saved password. The installer hands the result over in one line that is never shown.
- Second server: choose "add to <first server>" and the deployer signs in to the first panel (pinned certificate, or a publicly trusted one) and adds the new server. With 2FA on, it shows the join code to paste instead.
- Fixed: on a server still using its self-signed certificate, the join code pointed at http:// and was rejected as damaged.
- Fixed: the Windows deployer could read an empty exit code from ssh.

**Owner chores**
- VPS renewal reminder: enter the date the plan must be renewed (and where); Telegram reminds you 7, 3 and 1 days before and on the day, and the overview shows it.
- Lines the apps cannot reach: the vps2vpn app reports a line that keeps failing (`POST /s/<link>/api/report`, one vote per account, kept 24 hours, cleared when it works again). The overview names the line and how many accounts reported it, Telegram is told from two accounts on.
- "Use another port": moves REALITY, Hysteria 2 or TUIC to a fresh random port (outside the hopping range), opens it in ufw / firewalld and restarts the core, from the alert or from Settings.
- The member API (`/api/me`, also through the subscription link) includes the last AI check, so the app can show "Claude ✓ ChatGPT ✓" for the server.
- App updates from your own server: put the vps2vpn installers in `/var/lib/vps2vpn/client` (or enter a version and link in Settings) and `/api/me` offers the newest one; the app shows "new version" and opens the download in the browser. Downloads go through a valid subscription link only.

**Managing many users, like the mature panels**
- User list: filters (online, active, paused, expiring within 7 days, almost used up) with counts, sorting (order added, name, usage, expiry, last seen), multi-select with bulk enable / pause / extend / add GB / reset / new links / delete.
- Add many accounts at once (prefix-01, prefix-02 ...), export all users as CSV (opens in Excel).
- Device limit per user: over the limit, the account is paused for 10 minutes (or only reported, as you choose); events are logged with the addresses.
- Lifetime that starts on first use ("30 days from the first connection").
- Custom routing: your own direct / proxy / block domain lists, ahead of the built-in rules, in Clash, sing-box and Shadowrocket subscriptions.

**Security**
- Optional two-step sign-in (TOTP, any authenticator app), set up by scanning a QR code; turning it off needs the password.
- Sign-in history (time, address, device, success / wrong password / wrong code) and "sign out all other devices".

**Telegram**
- Bot commands from your own chat: /status, /users, /user NAME, /doctor, /backup. Other chats are ignored, and messages sent before the panel started are never acted on.
- The daily backup is also sent to Telegram (can be turned off).

**Overview**
- 24-hour server CPU, memory and network charts (5-minute averages, kept across restarts).

**Polish**
- Phone layout: panel titles no longer squeeze, the bulk bar sits above the tab bar, the 2FA screen stacks.
- Auto-refresh no longer replays the page animation every 5 seconds.
- The health-check card shows what it is for before the first run; the multi-server page says plainly that a single server can ignore it.

**Three protocols again**
- TUIC v5 is back (served by sing-box v1.14.4, hash-pinned), next to Hysteria 2 and VLESS + REALITY. Same per-user credentials; on/off and port in the panel; in Clash and sing-box subscriptions (pinned like Hysteria while the certificate is self-signed; share links list it only with a trusted certificate). Per-user TUIC traffic is measured from sing-box's connection list, with short-lived connections credited from the server totals.
- Paused users no longer receive any node (the TUIC entry is withheld too).

**Panel rebuilt on the original console's design system**
- Same tokens, components and canvas charts as the existing admin console: sidebar, live throughput, 30-day bars, service status, user drawer with QR / one-tap import / usage ring, light-dark-system theme, phone tab bar.

**Fixed**
- Found on a real VPS (AWS Lightsail, Ubuntu 24.04, 1 GB): a fresh install never started its proxies. The config was checked under a `.check` file name, which Xray refuses, so no config was written. The check file now ends in `.json`, and one rejected config no longer blocks the other cores.
- Buttons that POST without the server reading the body ("check now", "scan now") had their reply lost on real networks (connection reset). Every request body is now read before replying.
- Redeploying over a finished install printed the first-time setup link again, and the Windows / macOS deployers reported it as a failure. It now says the install is up to date and shows the panel address.
- `tools/bench.py` could not read Clash subscriptions that start with a comment line.
- The database is owner-only (600) as well as its directory.
- Two registrations racing for the last use of an invite code could both succeed; invite, register, request and approve steps now run one at a time.
- A node joined to two main servers would delete the other's accounts every minute; a node now belongs to one main server until its join code is renewed. Malformed credentials from a main server are skipped instead of breaking the cores.
- Typing a non-number as quota or server cap could silently mean "unlimited"; it is now refused.
- Renaming a user could create two accounts whose names differ only in case (member login is case-insensitive).
- Member login takes the same time whether or not the name exists.
- Every confirmation dialog showed a stray "null".
- Error messages from the server are shown in Chinese on Chinese pages.
- Extending an account's expiry also extends the accounts carved from its quota.
- After a certificate renewal that keeps the same file (IP certificates, every few days) Hysteria and TUIC are restarted so they stop serving the old certificate.

**Easier**
- The installer recognises AWS Lightsail / EC2, Oracle, Google Cloud, Azure, Alibaba and Tencent Cloud and says exactly where in that console to open the firewall.
- Windows deployer that needs nothing installed (`deploy-windows.bat` opens a window; uses Windows' own PowerShell, tar and ssh). Drop a key file or the whole `.ssh` folder on it, or type the password.
- macOS / Linux deployer `deploy-mac.command` (drag the key file into Terminal).
- Ports already in use (nginx, another panel) are detected on first install; vps2vpn moves to a free port and says who held it.
- Small servers get 1 GB swap; time sync is switched on; a failed upgrade rolls back to the previous version.

**Keeps itself running**
- Health check ("一键体检" in the panel, `vps2vpn doctor` on the server): services, camouflage site, Hysteria API, UDP port owner, port hopping, certificate, BBR, UDP buffers, clock, public address, internet access, disk, memory, core version, rule mirror; each failure comes with a fix.
- Watchdog restarts a dead core every 5 minutes at most.
- Public IP changes are followed automatically after two consecutive sightings (subscriptions, certificate and cores updated).
- Daily backups in `/var/lib/vps2vpn/backups`, 14 kept; `vps2vpn backup`.
- Optional Telegram alerts: 80 % quota, user paused, core down, IP changed, certificate renewal failing.
- Optional IPv6 entries in subscriptions.

**Faster**
- Server-side DNS adapts: encrypted DNS only when the resolver is reachable from the server, otherwise the system resolver. On a host where DoH is blocked, median fresh-request latency over REALITY went from 8.3 s to 0.38 s.
- `vps2vpn bench` (server) and `tools/bench.py` (your computer): latency median/p90 with fresh handshakes, 1- and 4-connection download, upload, direct baseline, JSON output.

**Members and invites** (ported from legend)
- Member centre at a private path and on every subscription link opened in a browser: usage ring, 30-day history, one-tap import (Clash, sing-box, Shadowrocket), QR, password change.
- Invite codes: admin codes (own quota and lifetime) and member codes that carve quota from the inviter, with limits on live codes, uses and validity; registration with `#register=CODE`.
- Quota requests from members, approved or rejected in the panel; approval re-enables a paused user.
- Admin notice on every member page; members see why they are paused, when they are about to expire or run out, and can replace a leaked subscription link themselves.

**Shadowrocket**
- Native Shadowrocket config (`?format=shadowrocket`) with the same rule sets as Clash, converted on the server (`/rules/*.list`), and a `shadowrocket://` import link.

**Watching**
- Online users and device count for all three protocols.
- Site monitor every 5 minutes: GitHub, YouTube, ChatGPT (with region check), Google, X, Telegram over IPv4/IPv6, plus a download speed test; 24 h history.
- Abuse guard (observes only, never pauses): scanning/relay pattern, link shared by many addresses, mail spam; event log and Telegram.
- Server monthly traffic with a cap and reset day, 80 % / 100 % alerts.

**Several servers, one subscription**
- Join another vps2vpn with a join code (certificate-pinned HTTPS). Users are pushed every minute, traffic comes back and counts toward the same quota; each server gets its own nodes and fallback group.

**Units**
- All sizes in the panel use 1 GB = 1024³ bytes, the same unit as quota fields.

**Quality**
- Verified on a real VPS: full acceptance 47/47 (including reinstall and uninstall + reinstall), and 27 live checks of members, bulk actions, batch creation, CSV export, custom routing, 2FA setup, sign-in history, invites, subscriptions, Shadowrocket rules, site monitor and abuse watch.
- 57 offline tests, 28 end-to-end checks with real cores and clients, `tests/vps_acceptance.sh` for a real server, GitHub Actions workflow (unit on 3.8/3.12, shellcheck, Linux e2e, real install + acceptance).

## 0.1.0

First version: one-command install, setup wizard, Hysteria 2 + VLESS/REALITY, multi-user quotas, Let's Encrypt IP certificates, subscriptions for Clash/mihomo, Shadowrocket, sing-box, Hiddify and v2rayN/NG, mirrored rule sets, automatic network tuning.
