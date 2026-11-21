# Changelog

## Unreleased

**For the owner**
- Telegram reminds you when an account ends: 3 days before and again the day before (working accounts only; extending it and letting it run out again reminds you again). New bot command `/expiring` lists accounts that end within 7 days or have used 80% of their quota.
- Day-scale reminders (account expiry, 80% of quota, VPS renewal) are remembered in the database, so an upgrade or restart no longer sends them again.

**Subscriptions**
- A working account that ends within 7 days or has used 90% of its quota (after what it shares with invitees) gets an `Announce` line in its app saying so (Happ, Hiddify, Streisand… show it), the same heads-up as on the member page.
- How often apps refresh the subscription (`Profile-Update-Interval`) is a setting now: 1–168 hours, default 12 as before.

## 0.2.7

Review PRs #50, #52, #57, #58, #61, #62, #64, #66 and issues #67–#71.

**Security**
- A logged-in session can no longer replace an enrolled admin 2FA authenticator; turning 2FA off (which needs the password) comes first.
- Telegram: a malformed `getUpdates` record no longer kills the command thread, an absurd `update_id` cannot poison the polling cursor, and a rejected offset is reset instead of retried forever.

**Correctness**
- Bulk actions over 2000 IDs are refused with 400 instead of silently applying to the first 2000; an out-of-range number answers 400 instead of 500.
- Account expiry is bounded (up to 9999-12-31) before it reaches the database, and a bulk extend checks every account before changing any.
- Alert deduplication is per recipient: rebinding to a new chat no longer swallows the first warning, and two identical alerts at the same moment are sent once.
- The hourly forced speed check really runs, and is retried on the next tick when the monitor is busy.
- A `history.json` that is valid JSON but not a list no longer stops the scheduler from starting.
- Cold Shadowrocket rule requests no longer pile up behind one slow upstream fetch (which could exhaust the panel's request threads); they get the file or an immediate 503.

## 0.2.6

**Fewer disconnects**
- Adding a user (or switching one back on) no longer restarts Xray: the new users are handed to the running core through its API, so nobody else is disconnected. Any other change, a failed call, or removing/disabling a user still restarts it — Xray has no way to close a removed user's open connections, and a cut-off must really cut off.
- Traffic counted since the last reading is saved right before a core restarts instead of being lost, and counters are read every 20 s instead of every 60 s.
- A renewed certificate no longer restarts Hysteria 2 or TUIC: both pick up the new files for new connections by themselves (Hysteria re-reads them per handshake, sing-box watches the files).
- Hysteria 2 and TUIC restart only when their own config changed. (A non-ASCII certificate path no longer made TUIC restart on every apply.)

**Subscriptions**
- Apps the panel does not know by name (Happ, Streisand, V2Box…) get the share-link list instead of the web page; the page is shown only to clients that ask for HTML.
- Subscriptions carry `Profile-Title`, `Profile-Web-Page-Url` (the user's own page), an optional `Support-Url` (new setting: http(s) or tg:// link) and, for a stopped account, an `Announce` line saying why.
- A stopped account (quota used up, expired, paused for too many devices, or disabled) shows one dead entry named with the reason in every format, so the person sees why it stopped; traffic stays blocked and no server details are in it.
- The admin user list shows when each subscription was last downloaded and by which app.

**Install and upgrade**
- `install.sh` installs the latest tagged release instead of the tip of `main`, and checks the release's SHA-256 file before unpacking anything (a mismatch stops the install). Each release now carries a reproducible source tarball and its checksum. `V2V_REF=main` is the explicit, unverified development path.
- Every upgrade first saves a consistent copy of the database (SQLite online backup, integrity-checked) and the previous panel code; the last three are kept, and the one-line rollback command is printed. An upgrade never silently downgrades.

**Reliability**
- Rule mirror: a downloaded `.mrs` must be a complete Zstandard frame sequence and a `.srs` a complete zlib stream with a valid checksum (decoded in small pieces, never held in memory), so a cut-off download is not published (from #48). Any SRS version from 1 up is accepted, so a newer sing-box format is not refused.

## 0.2.5

Follow-up on the integrated review of all earlier audit reports, plus review PRs #9, #11, #12, #18, #20, #22, #24–#26, #30, #31, #34, #36, #39, #41–#44 and #46.

**Security**
- Telegram pairing: the panel shows a one-time `/bind` code; only the private chat whose own user sends it can become the alert and backup recipient (from #11). Bot commands are answered only in that private chat and only when the owner sent them, never from a group that happens to share the id (from #9).
- Joined servers learn each account's expiry date, so an expired account stops there too, even while the main server is unreachable.
- A sync round that was in flight while a backup was restored, or while a server was re-added with new credentials, drops its answers instead of billing traffic to whichever accounts the old ids now name.
- The health check says plainly when subscription links use plain HTTP (self-signed certificate), and how to get them encrypted.
- Switching the Telegram bot off (or to another chat) also stops commands already in progress: no reply, backup or remaining text goes out under the old setting (from #26).
- The main server re-checks a joined server's DNS name on every sync and connects only to the public addresses it checked, so a name that later points inside the network is refused; a node's refusal or malformed answer is no longer taken as a successful sync (from #24).
- Changing a subscription link (by the admin, in bulk, or by the member) also ends every member-centre login made with the old one, so a leaked link cannot keep a session open; a member who changes it from the member centre stays logged in with a new session (from #46).
- **Upgrade note:** a Telegram recipient saved by an older version (or restored from a backup) is no longer trusted on its own: alerts, backups and bot commands pause until you send the panel's `/bind` command once. The System page says so; the saved bot token can be reused (from #36).
- Turning a user or a joined server off with `"enabled": "false"` (or any text) now really turns it off; values that are neither true nor false are refused with a 400 (from #31).
- Bulk actions apply once per account even when an id is listed twice (no double quota or expiry), and refuse an id list that is not an array of whole numbers (from #34).

**Reliability**
- Switching a protocol back on starts its service even when its config did not change, and a service that fails to start is reported and retried instead of shown as fine.
- TUIC traffic: a missed reading no longer loses the traffic in between, rounding leftovers are carried instead of dropped, and malformed numbers from any core are ignored instead of stopping the count (or billing negative traffic).
- Certificates: the key and certificate are installed as a pair (the old key is put back if the certificate cannot be written), a certificate from an already-finished ACME order that does not fit the new key is refused, and a self-signed certificate whose key went missing is recreated.
- Rule mirror: truncated downloads and HTTP-200 error pages are no longer published as rule sets (from #12), and a first Shadowrocket request that converts to nothing is not cached as an empty rule set (from #25).
- Monitor: the bandwidth probe counts only a complete, uncompressed payload (from #18); a damaged history or AI-check file is skipped row by row instead of breaking the page (from #22); one malformed stream in the abuse scan no longer hides all the others (from #20).
- Online-user and TUIC traffic counting skip malformed records from Hysteria and sing-box instead of stopping (an oversized or non-ASCII account tag included), and a malformed connection list no longer resets the traffic baseline (from #30).
- Sync: a node answer must say `ok: true` (every version since 0.2.0 does), and a join code or saved node address with a broken or zero port is refused instead of failing later (from #43, #44).
- The abuse scan treats a malformed Hysteria or TUIC stream list as "not measured" instead of as zero streams (from #42).
- Rule mirror: a `.mrs` file must start with a Zstandard frame and a `.srs` file with `SRS`, so a plain-text HTTP-200 error page can no longer replace a good rule set (from #39).
- Client updates: the panel also recognises the client's current file names (`vps2vpn-dev-1.0.4-…-windows-amd64-setup.exe`, nightly and `rs` builds), picks one default file per system, and orders versions correctly (1.0.4 above 1.0.4-nightly, rs.10 above rs.2) (from #41).
- QR codes refuse text that does not fit instead of cutting the link short; the invite "revoke" button works again; with no users, configs no longer change (and restart the cores) on every apply; the "server unreachable" alert is sent outside the database transaction.

## 0.2.4

Review of the outside fixes proposed for 0.2.3 (#5–#8): taken where they hold up, adjusted where they did not.

**Security**
- A server whose protocols are all switched off no longer hands out subscriptions that quietly fall back to a direct connection: Clash, sing-box and Shadowrocket profiles then block traffic instead (checked with the real mihomo and sing-box).
- Joined servers refuse a damaged account list from the main server as a whole, instead of reading its bad rows as deletions; the update is one transaction, and the main server is told why (HTTP 400).
- A Let's Encrypt certificate only counts as trusted when its chain verifies against the system roots and the key matches.
- The public-IP lookup only accepts a public address of the right family.
- Telegram: the alert chat is chosen from private chats first (not a group the bot sits in), and alerts and backups always go to the chat set *now*, even from a job that started before you changed or switched it off.
- When reloading the cores fails, it is retried (1 min, then up to every 15 min) so a disabled account cannot keep connecting until the next change.
- Two installs started at once (a retried or double-clicked deploy) now run one after the other.
- Port-hopping rules file and the AI check result are no longer world-readable.

**Reliability**
- Speed test: Cloudflare's download test is rate-limited and refused from some data centres, which showed as "0 Mb". The test now moves on to other public test files, also when a source breaks off mid-test.
- Not taken from the review: switching off Xray's sniffed destination. Apps that resolve names on the phone (often with tampered DNS) rely on it to reach Google and others; spoofed names are already resolved on the server and stopped by the private-address block.

**Tests and CI**
- CI installs the way the one-click deployers do, measures speed against a local test source and prints service logs on failure; all five jobs are green again.

## 0.2.3

Fixes from a third outside code review (on 0.2.2).

**Security**
- One-click deployers only open links of known kinds (vps2vpn://, clash://, hiddify://, sing-box://, shadowrocket://, http(s)). A hostile server can no longer make your computer open a file or script, and the deploy page no longer renders unchecked links.
- The browser deployer remembers each server's SSH fingerprint (in your vps2vpn folder). If a server's identity changes it stops and explains what to do; after reinstalling a server's system, that is expected.
- Windows deployer starts PowerShell by its full path.
- Users cannot reach the server's own private addresses (cloud metadata, local services) through the proxy, even with a fake domain name.
- When every account is disabled, nobody can still use the TUIC line, and Hysteria 2 no longer crash-loops.
- Requests: conflicting or malformed length headers, endless trailers and huge passwords are refused early; at most 128 connections at once.
- 2FA codes cannot be reused; failed attempts from one IPv6 network are counted together; CSV export is safe to open in spreadsheets.
- Invites: paused accounts and multi-level invites can no longer be used to recycle quota; an unused invite code is no longer voided by the inviter spending their kept 1 GB.

**Reliability**
- Port-hopping firewall rules and BBR now survive a reboot (checked on a real server).
- Certificates: IPv6 addresses and full-chain certificates are matched correctly.
- sing-box subscriptions: port hopping no longer conflicts with the main port.
- Cores start on servers without IPv6. Hysteria 2 always uses BBR (clients cannot demand a fixed send rate).
- Online count, monitoring and config reloads no longer block each other; the scheduler is not confused by clock changes.
- Database indexes; restored backups no longer keep old sessions or traffic history.
- Installer: works with SELinux, XFS/Btrfs swap and RHEL's curl; a failed upgrade puts the previous version back.
- Panel: fixed a chart that kept redrawing forever, date off-by-one, a crash when the session expired, and missing sign-out / theme on phones.
- The member API also answers download requests over plain http with 426 (with an Upgrade header), and download links are https.

## 0.2.2

Fixes from a second outside code review.

**Security**
- Panel API: a fixed list of endpoints, each with its allowed methods (anything else is 404 / 405). The user list no longer sends account secrets to the browser.
- Request bodies: Content-Length and chunk sizes are checked strictly; a bad size is a 400 instead of an error.
- Login lockout counts are safe under parallel requests. Changing the admin or a member password, or restoring a backup, signs out other sessions.
- Firewall rules are replaced in one step (no open moment), and only apply to outside traffic.
- Cluster join: a join code without a pinned certificate is no longer tried over an unverified connection; sync requests are handled one at a time.
- Certificate fingerprints read only the server's own certificate; the public-IP lookup uses verified TLS; Telegram bot tokens are hidden in logs.
- Database: busy timeout, transactions for multi-step changes, and a whitelist for imported columns.

**Reliability**
- Settings and config files are written atomically. Rule downloads fall back to a second mirror.
- Quota requests are charged correctly; invite limits count codes already used.
- Hysteria 2 online counts fixed; QUIC buffer sizes follow the server's memory.
- Subscriptions: empty groups fall back cleanly, duplicate names are avoided, Shadowrocket labels are escaped, and sing-box DNS rules only name rule sets that exist.
- Panel: dates shown in local time, search works with Chinese input methods, Escape closes dialogs once.
- Installer and deployer: small fixes (a shell variable name clash; a deploy is only "ok" when the panel check actually ran).

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
