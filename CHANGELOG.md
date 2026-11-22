# Changelog

## 0.2.27

- **Line order: TCP first.** A new switch under routing in the panel puts Reality (TCP) ahead of Hysteria 2 and TUIC (UDP) on every server in the subscription, for networks that slow UDP down. IPv4 entries stay ahead of their IPv6 copies. Off by default; nothing changes until you turn it on.
  **线路优先顺序：TCP 优先。** 面板「分流」里新增开关：订阅里每台服务器先用 Reality（TCP），再用 Hysteria 2 / TUIC（UDP），适合 UDP 常被限速的网络。默认关闭。
- An approved top-up now lifts a slow-down at once, when the new quota covers what was used.
  批准加流量后，如果新额度够用，降速立刻解除。
- Speed-limit cleanup also removes an ingress qdisc that a failed setup left with only its connmark step, but only next to our own root qdisc.
  限速清理时，失败残留的入站规则也会清掉（只清我们自己的）。
- Quota checks settle invite trees up to 32 levels deep in one run; billing on a server with a traffic rate never goes below zero.
  多层邀请的流量结算一次最多处理 32 层；倍率计费不会出现负数。

## 0.2.26

Fixes from a sixth outside review of the speed-limit and slow-down features.

**Speed limits and slowing down**
- On a server with only Hysteria 2 on, a limited account is no longer locked out: Hysteria cannot hold one account to a speed, so there it keeps Hysteria at full speed (as its subscription already assumed), and "slow down instead of stopping" stops the account as on a server without limits.
- An account switched off by hand or paused for its devices is not "slowed down" (and not reported as such) when its quota runs out; it stays off.
- After a top-up that is used up again in the same period, the owner is told about the slow-down again, and a manual traffic reset re-arms that message too.
- The kernel's speed classes get a fixed quantum, so 1-5 Mbps slow-downs no longer make the kernel warn and burst; an empty ingress queue left by a failed attempt is cleaned up instead of blocking every later one. Odd values (not a finite number) are ignored.

**Accounts and invites**
- Someone who registers with a member's invite code gets the servers and speed limits the member has now, not the ones when the code was made, so tightening a member also covers codes already handed out.
- Invite trees more than two levels deep settle in one quota check.

**Subscriptions and pages**
- A joined server whose name clashes with another keeps its "x2" rate in the group name.
- The member page counts only the servers this member may use and that are not paused.
- "No vps2vpn app yet?" on the member page downloads the installer from this panel when it holds one (GitHub is often out of reach before the app is installed).
- The plain subscription page shows 0 B, not 1 B, for an account that shared all its quota, and names the app in English on an English panel.

**Tests**
- The installer's snapshot test matches its bilingual rollback hint (CI had failed since 0.2.23).

## 0.2.25

- Google Play downloads no longer stall in China. Its `services.googleapis.cn` (and `google.cn`) matched the China list's catch-all ".cn goes direct" rule, but these names lead to Google servers that are blocked there; they now go through the proxy in every app format. An owner's own direct list still wins.

## 0.2.24

- The member page and the plain subscription page have an "Open in the vps2vpn app" button: one tap opens the vps2vpn client and imports the subscription, with a download link under it. On Windows it is the main button, and the app lists now recommend the vps2vpn client (macOS still recommends Clash Verge Rev).
- The one-click deploy page uses the same look as the owner panel. On Windows, when no VPN app is found, it offers the vps2vpn client. The "clear chosen key" button only shows once a key is chosen, and the tab title is in Chinese.

## 0.2.23

- The owner panel keeps the open page in the address (for example `#users`). Reloading, or reopening the panel on a phone, stays on that page instead of jumping back to the overview, and the browser's or phone's Back button returns to the previous page instead of leaving the panel.
- On a phone, Back closes an open account panel first, instead of switching pages under it.
- The one-click deployer writes its install log in Chinese (the server's install steps in English and Chinese). The deploy page opens this log by itself when something fails, so you can see which step stopped without reading English.

## 0.2.22

- An account set to expire "N days from first use" now starts its clock on a x0 (free) server too. There its traffic is billed as 0 bytes, so before, the clock never started and the account never expired.

## 0.2.21

The member page, walked through as a member would use it, plus two clearer labels in the owner panel.

**Member page**
- Opened inside WeChat or QQ, the page says to use "Open in browser" (those apps cannot hand a link to a VPN app).
- "Invite friends" says plainly that a friend's share leaves your monthly quota as soon as they register, and how to take it back.
- GB promised to unused invite codes is shown, and "left" counts it. A code the inviter can no longer honour is marked void instead of "usable".
- Changing the subscription link shows the new link at once, with a copy button. Opened from the personal link, the warning says this page's address stops working too.
- A taken name or a short password at sign-up keeps the typed passwords and no longer counts toward the wrong-code limit.
- Stash and Karing get their own import buttons, and the app list says which iPhone apps cost money.
- The subscription landing page shows the same quota as the member page (with top-ups, minus shares).
- Opened from the personal link, a new password can be set without the old one.

**Owner panel**
- The users list says "resets on day N each month" and "at most N devices" instead of bare symbols; the server pause and sync buttons explain themselves on hover.

## 0.2.20

The rest of the owner-panel walkthrough.

**Joined servers**
- On a joined server, the main server's accounts are shown read-only, with a note to change them on the main server. They used to look editable, but every change was ignored or undone at the next sync (a deleted account came back). Single and bulk actions on them are refused while the server is joined. Once it has left, the leftovers can be deleted.

**Settings**
- With a domain set, typing a different server address is refused with a reason, instead of being silently replaced by the domain. Clearing the domain asks for this server's IP, instead of leaving subscriptions on the old domain and automatic IP repair off.

**Overview**
- The 30-day traffic figure adds up the same 30 days as the chart (it counted 31), and is labelled as user traffic as billed. A ×2 server counts double there, unlike "this server, this month".

**One-click deploy and installer**
- `deploy-mac.command` and `install.sh` are executable in the repository, so double-clicking the macOS deployer from the GitHub zip no longer says "no access privileges".
- Double-clicking `deploy-windows.bat` inside the zip (without extracting) says to extract the zip first, instead of asking to install Python.
- `install.sh` explains its three common errors (not root, download failed, panel failed to start) in Chinese too, with what to do next.
- README: extract first, the simplest firewall rule, and how phones import from the Windows window.

## 0.2.19

A walk through the owner's panel, as an owner running it for family and friends would use it.

**Moving, pausing and removing servers**
- Restoring a backup on a new server keeps this panel's secret path and port, and this server's address unless the backup has a domain. Before, the page went to "404" right after "restored", and subscriptions pointed at the old server's IP.
- A restore keeps this period's approved top-ups (0.2.18 left them out).
- Removing a joined server takes it out of every account and invite code that named it. Someone limited to that server alone keeps this server, instead of an empty subscription.
- A paused joined server is still synced, with every account switched off there. Before, people paused or removed meanwhile kept using it, and its traffic went uncounted until it was resumed.

**Accounts**
- Quotas and speeds with decimals (2.5 GB from a member's invite, 0.5 GB added in bulk) can be saved in Edit. The form used to refuse them with a browser bubble.
- "Slow down instead of stopping" applies only where speed limits hold. On a server without them (a container VPS), an account that used up its quota stops as before, instead of running unlimited.
- An account that shared its whole quota with invitees shows as used up, not "unlimited".
- Switching on an account that is expired or out of quota says why it stays paused, instead of "saved" (one account or in bulk).
- The account details label the total after shares and top-ups "实际可用额度", with the plan beside it.

**Wording**
- Bulk "加流量" is now "永久提高上限", which is what it does. Approving a request is the top-up for this period. The approve dialog names the field to change for good (「流量上限」) and says that an account without a reset day keeps a top-up until its traffic is reset by hand. Resetting traffic warns that the top-up ends too.
- The Telegram pairing command no longer changes when the page refreshes after it was sent to the bot.

## 0.2.18

A walk through the member page and the owner's request queue, as a member and as the owner would use them.

**Traffic requests**
- Approving a member's request for more traffic is now a top-up for the current period. It ends at the account's next traffic reset (the monthly one, or a reset by hand). Before, it raised the monthly plan for good, which neither side expected. The approve dialog says so; to raise a plan for good, change the quota under Edit. The member page and the account's details both show "+X GB this period", and backups carry it. A slowed-down account speeds up again as soon as the top-up covers what it used.

**Member page**
- A paused account's usage bar in the app now shows the same total as the member page. It used to show the plan without taking off the share given to invitees.
- Members can only make invite codes while the member centre (the sign-up page) is on. The password section is hidden when there is no login page to use it on.
- "Create code" copies the ready sign-up link instead of the bare code, and the suggested amount never exceeds what can still be shared.
- The "quota used up" notice only suggests asking for more when requests are on. It gives the reset date, or says to ask the admin when the account never resets.
- "Too many devices" names the limit and says to close the extra devices. An account that expires N days after first use says so instead of "never". Unlimited accounts no longer see a request form they cannot use.

**One-click deploy and installer**
- The deployers refuse a PuTTY `.ppk`, a public key or a passphrase-protected key up front and say what to use instead.
- A server that wants another login user (AWS: "Please login as the user ubuntu") is retried once as that user; the macOS deployer without Python names the user to try. Only AWS-named `.pem` keys default to `ubuntu` now, not every `.pem`.
- The macOS deployer accepts a key with Windows line endings; the web deployer checks that Windows' own OpenSSH is new enough before a password login.
- While the cloud firewall still blocks the lines, the finish screens (web, Windows, macOS) say "one more step" instead of "done", and list what to do next: add people, add a server, upgrade. The macOS one no longer says no VPN app was found when one was.
- `install.sh` run through `curl | bash` no longer picks up a `vps2vpn` folder in the current directory instead of the verified release.

## 0.2.17

**Airport features**
- **Speed limit per account** (Mbps). Set it on the account, on an invite code (accounts made from it get it), or leave it at 0 for none. It holds on every server the account uses: the main server sends each joined server the speed to keep.
- **Slow down instead of stopping**: an account can be given a slow-down speed for when its quota is used up. It then keeps working at that speed until the monthly reset or more quota, and the member page, the apps' notice line and Telegram say so. With no slow-down speed an account stops as before.
- **Servers per account**: with several servers, an account (or an invite code) can be limited to some of them. By default it may use all of them, including ones added later. Member invite codes carry the inviter's servers and speed settings.
- **Traffic rate per server**: each joined server, and this one, can count its traffic at a rate (x2, x0.5, 0 = free), as airports do. Group names in subscriptions show it ("Tokyo x2").

**How speed limits work**
- Xray (Reality) and sing-box (TUIC) mark a limited account's connections and the kernel's traffic control (tc HTB with an ifb device for download) holds them to the speed. Other accounts are untouched.
- Hysteria 2 cannot limit one account, so a limited account gets no Hysteria 2 entries where limits work; Reality and TUIC stay.
- Container VPSes (OpenVZ, LXC) lack tc/ifb: the panel says so, the self-check reports it, and limited accounts run at full speed.
- Upgrade with the install command as usual: it also lets the Xray and TUIC services mark traffic. A server whose services cannot mark yet keeps limited accounts at full speed, and the self-check says how to fix it.

**Backup and restore**
- Backups carry the new account and invite fields and the rates; a restore checks them.

## 0.2.16

**Telegram**
- Pairing the bot works while the panel's command bot is already polling the same token: the panel remembers `/bind` messages it has seen for 15 minutes, so the pairing step no longer loses them to the other poller (Telegram's 409 "conflict"). `/bind@yourbot <code>` (the form Telegram fills in from the command menu) is accepted too.

**Subscriptions**
- Shadowrocket rules built from an upstream list skip domain entries with commas, spaces or other odd characters, which could otherwise add a rule of their own or an empty one.
- When only part of the rule lists could be fetched on first start, the rest are tried again every hour instead of waiting a day.

**Backup and restore**
- A restore checks every invite field that sign-up and the quota maths read (code, kind, quota, uses, valid until, status) and refuses a backup with a bad or duplicate code before anything is replaced. A good restore also forgets the old install's alert history.

**Abuse watch**
- Dozens of different hosts on one remote-login, file-share or database port (SSH, RDP, SMB, MySQL …) now count as a wide scan, not only hundreds of targets on many ports. Ordinary browsing on 443 does not. The Hysteria stream list is read with a 16 MB limit.

**App downloads**
- An installer shorter than its announced size is treated as a failed download, and a full disk while publishing leaves neither a half-published platform nor temp files behind; it is tried again later.

**Admin**
- `vps2vpn reset-password` refuses passwords over 128 characters and a blank or control-character username, so it cannot leave an admin that the sign-in page then refuses.
- Passwords and tokens with a lone surrogate character are a wrong answer, not an internal error.
- The client-update and IP-recheck jobs cannot run twice at once; the certificate-name cache also notices a certificate replaced on another disk.

## 0.2.15

**Telegram alerts**
- When Telegram does not answer (timeout, DNS, connection refused), alerts are held back for a minute instead of each one waiting out its own 10-second timeout in turn. Twenty accounts at 80% of their quota used to hold the 20-second quota and expiry pass for minutes. Held-back alerts are sent on a later round, like any failed one; a reply from Telegram (even a refusal or a rate limit) does not hold anything back.

**App reports**
- A line report from the app whose host has line breaks, spaces or control characters is refused: the host is quoted in the admin's alert, and such text could make it say something else.

## 0.2.14

**Accounting**
- After a restore, TUIC traffic that was still waiting to be split between users (connections that opened and closed between two samples) is dropped with the rest of the old accounts' counts, instead of going to whoever the backup gives the same account number (#106). A restore that fails keeps it.

**Access**
- When writing the new configs fails after an account was stopped (quota, expiry), the scheduler tries again with backoff (1, 2, 4 … 15 min) instead of waiting for the next unrelated change; until then the cores still let that account in.
- A device-limit pause no longer replaces an admin turning the account off at the same moment, which used to switch it back on by itself after 10 minutes.

**App downloads**
- An installer is sent from one open file, so a client update swapping in a newer one mid-request can no longer mix the size of one with the bytes of the other; links in the folder are not followed.
- Installers, signatures and the list of fetched files are kept private (0600) like the rest of `/var/lib/vps2vpn`, and each one is recorded as fetched as soon as it is published, so it is cleaned up later even if that round stopped early (PR #118).

**Panel**
- `/<panel path>` without the trailing slash redirects to it (the page's links only work there).
- Text that is not valid Unicode (a lone surrogate) is refused with 400 instead of an internal error; an admin username that is blank or has control characters is refused.
- The QR code image gets the same sandboxing header as the other SVGs; after an error mid-reply the connection is closed.
- A restored backup that lacks some keys (an older or hand-made one) gets them at once instead of at the next restart.

## 0.2.13

**Client app**
- Clash profiles carry the panel's certificate pin (`x-vps2vpn-pin`), so the vps2vpn app (1.0.10+) checks the panel with it when it reports a line or downloads an update, also on a subscription that is paused or has no nodes.
- The version the panel offers the apps is the newer of the one fetched from GitHub and one set by hand. A manual entry older than the fetched one no longer hides it (or its download link); a newer one wins without the fetched files.
- When one platform's installer fails to download or check, the others are still published.

**Connections and limits**
- Per-client connection limits and login rate limits count an IPv4 client reaching a dual-stack panel (`::ffff:1.2.3.4`) or with an IPv6 zone as the same client, not as a separate one.
- Addresses that embed a private IPv4 (IPv4-mapped, 6to4, Teredo, NAT64) count as private: they cannot be set as the Reality camouflage target or the Hysteria masquerade page, and are not taken for this server's public address when several servers join.
- Port hopping redirects only traffic arriving from outside the server, not the server's own local UDP.
- A request with a body the panel does not read gets its connection closed instead of the panel reading up to 8 MiB of it.
- Device limits count Xray clients connecting over IPv6 or as an IPv4-mapped address, which Xray's online list showed but the panel skipped.

**Accounts and invites**
- Deleting an account hands its share to invitees that still count against it (live, or paused for quota or devices) before expired ones.
- An expired account is not turned back on by approving a traffic request; an account without a traffic limit cannot request more.
- The Telegram `/users` list shows the quota an account can really use after what it shares with its invitees.
- Two admin 2FA enrollments at the same moment can no longer both pass the "2FA is already on" check: it is made under the 2FA lock.

**Background jobs**
- The public-IP check runs beside the 20-second traffic, quota and expiry pass instead of holding it up for its timeouts.
- TUIC without DNS-over-HTTPS resolves with the system resolver explicitly, as sing-box 1.14 requires.

**Subscriptions**
- A support URL with emoji or other non-BMP characters is kept; Facebook's and Instagram's in-app browsers ("MetaIAB") are no longer taken for a Clash Meta client.

**One-click deploy**
- The deployers remember the server's SSH key between runs next to the saved logins (Windows, macOS and Linux, in the same file), so a server whose key changed is refused with a hint (`ssh-keygen -R`, with the port) instead of trusted again; a records folder with spaces or `%` in its path works. The local deploy page no longer drops the connection on a token with non-ASCII characters. On Linux the subscription page opens with `xdg-open`.

## 0.2.12

**Sign-in**
- A sign-in, password change or 2FA disable that was still checking an old password when another request changed the password or 2FA no longer gets through: it is refused (409) instead of starting a session with credentials that no longer count, or putting back a password that was just replaced (#102, #110, #114).

**Restore**
- A backup the panel could not use is refused before anything is replaced: an unusable admin password hash, user name or 2FA secret (which would lock you out), request rows without numeric amounts, invite usage that is not a list of account numbers, or joined servers whose saved details fail the checks a sync makes (#101, #107, #109, #111).
- Shadowrocket subscriptions keep a restored account name, password or UUID with line breaks on one line instead of letting it add sections (#113).
- Traffic that was read from the cores but could not be saved yet is no longer billed after a restore to whoever the backup gives the same account number: the restore resets the cores' counters under the old accounts and drops what was pending. A restore that fails keeps it for the old account.

**Several servers**
- A joined server's TLS details may only carry the name, pin and certificate: other fields could replace a member's proxy password or host (#108). A joined server whose name is only line breaks or spaces is named "server" (#100).

**Client updates**
- When an earlier fetch got only some platforms' installers of the newest client (one had a bad signature, say), the missing ones are fetched on the next round instead of never (#117).

**Background jobs**
- A slow certificate renewal or Telegram backup upload no longer holds up the 20-second traffic, quota and expiry pass (#112).

## 0.2.11

**Client updates**
- The panel keeps the app installers members download at the newest vps2vpn client release by itself: every 6 hours it asks GitHub for the latest release and fetches the installer each platform updates itself from (the Windows setup program, an Android APK) with its `.sig`. It is published only when that is the release key's signature for it, the same check the app makes. Older copies it fetched itself are removed; installers you put in `/var/lib/vps2vpn/client` by hand stay. Settings → app updates → "Fetch the newest app from GitHub" turns it off. From client 1.0.9 the apps download a newer version in the background and install it with one tap.

**Accounting**
- Traffic read from Xray, Hysteria or TUIC (reading resets their counters) is no longer lost when the database write fails (locked, disk full): it is kept and billed with the next successful reading, once. Expiry and quotas are still enforced on a tick whose reading failed (#96).

**Several servers**
- A node whose answer has malformed server details or account mappings (a port that is not a number, a missing Reality key, a host with a line break, an ID like `"01"`) is refused before it is saved. It used to be stored and then break every subscription format for the accounts it served; now the node is marked failed and the last good details stay in use (#94; PR #98).

**Restore**
- A backup whose quota is an integer too large for a float (such as 2^1100) is refused with a clear message instead of an internal error (#95).

## 0.2.10

**Security**
- A panel with a trusted certificate (a domain with Let's Encrypt) no longer sends a subscription, with the account's proxy credentials, over plain HTTP: `http://` subscription links get a redirect to HTTPS first (apps follow it, so old links keep working). A self-signed panel still serves plain HTTP, which most apps need there (#84).
- Turning admin 2FA off and enrolling a new authenticator at the same moment can no longer leave 2FA silently off after the enrollment said it succeeded (#78).

**Restore**
- A backup whose panel or member-centre path is not a plain path segment (a number, a list, `../admin`, empty on a configured panel, or both the same) is refused before anything is replaced, instead of locking the admin out of the panel (#81, #82).
- Every user row of a backup is checked first as well: whole numbers within SQLite's range, finite quotas, text where text belongs. A row with `"expire_at": "not-a-number"` used to be stored as text and break that account's subscription on every request (#85).

**Robustness**
- Numbers like `1e400` or a 310-digit integer in a request answer 400 instead of 500 in batch creation, invites, member invite revoke, quota requests and the port, server cap and reset-day settings (#72, #74, #86; PRs #75, #79, #87).
- Several servers: a node answering an error as a JSON array or `null` no longer aborts the whole sync round, and node traffic counters that would not fit SQLite's 64-bit integers are refused (the node is marked failed, nothing is billed, the other nodes still sync) (#76, #77, #90; PRs #80, #83).
- Several servers: a node reporting the same account under two spellings of its ID (`"1"` and `"01"`) can no longer bill it twice; such an answer is refused like any malformed one. All traffic, the panel's own included, goes through one guarded write that keeps the counters exact whole numbers, and usage of an account deleted mid-count is dropped without losing everyone else's (#88; PR #83).

**Subscriptions**
- A joined server whose name contains a line break (it comes from the join code) can no longer add stray lines or sections to the Shadowrocket subscription; control characters in names become a space (#92; PR #93).

## 0.2.9

**Client updates**
- The panel serves the update signature `<installer>.sig` next to each installer in `/var/lib/vps2vpn/client` (at most 4 KB), and the settings page warns about installers that have none. From vps2vpn client 1.0.8 the app keeps an update only when it carries the release key's signature and is newer than the installed version, so a server that was tampered with cannot hand out a different installer. Copy the `.sig` files from the client's GitHub release along with the installers.

## 0.2.8

**For the owner**
- Telegram reminds you when an account ends: 3 days before and again the day before (working accounts only; extending it and letting it run out again reminds you again). New bot command `/expiring` lists accounts that end within 7 days or have used 80% of their quota.
- Day-scale reminders (account expiry, 80% of quota, VPS renewal) are remembered in the database, so an upgrade or restart no longer sends them again.

**Subscriptions**
- A working account that ends within 7 days or has used 90% of its quota (after what it shares with invitees) gets an `Announce` line in its app saying so (Happ, Hiddify, Streisand… show it), the same heads-up as on the member page.
- How often apps refresh the subscription (`Profile-Update-Interval`) is a setting now: 1–168 hours, default 12 as before.

**Correctness**
- The 80% quota reminder follows the account's own billing period (its reset day), not the calendar month, and a manual traffic reset or a quota change arms it again.
- An invitee of an "N days from first use" account that has not started yet gets the same countdown instead of never expiring.
- Approving a quota request that is still below what the account has used no longer switches it back on (it was switched off again a minute later, and so on).
- Device count: one phone on a dual-stack network, on the smart line, or rotating IPv6 privacy addresses counts once (IPv6 addresses are grouped by /64), so a device limit of 1 no longer pauses it and the abuse check no longer calls it a shared link.
- An account that shares part of its quota with invitees shows the quota it is actually cut off at in the apps (`Subscription-Userinfo`), not the full plan; one that shared all of it no longer shows as unlimited there, on its member page, or to an approved top-up that does not cover it.
- The server's monthly traffic (and its cap alerts) counts the physical network card only, as the provider bills it: Docker, WireGuard or tun links no longer count the same traffic twice, and one of them going away no longer looks like a reboot that adds everything since boot again.
- The Telegram settings list the `/expiring` command.
- "Too many devices" events are logged at most once an hour per account, so a warn-only limit no longer pushes every other event out of the log.
- One address can hold at most 16 of the panel's 128 connection slots, so a single client opening many slow connections cannot lock everyone else out (connections from the machine itself, such as a reverse proxy, are not capped).

**Security** (audit 2026-11-21)
- Sign-in lockout: logging in to a member account you own no longer resets the failure count, so it can no longer be used to keep guessing the admin password, another member's password or invite codes. Admin and member sign-ins are counted separately (members' typos never lock the admin out), and parallel guesses are counted as they start, so a burst of simultaneous requests gets 8 tries, not one per request thread.
- Changing the admin or a member password now checks the current one against the same lockout (a stolen session or a leaked subscription link could guess it without limit); an admin password over 128 characters, which sign-in refuses, can no longer be set.
- Turning admin 2FA on or off, and changing a member password, end every session including a stolen copy of the current cookie; the browser that made the change gets a new one.
- Request errors in the log no longer contain subscription tokens or the secret panel and member-centre paths.
- The member page's Content-Security-Policy also restricts `base-uri`, `form-action` and `object-src`.

**Docs**
- README rewritten for owners who share a server with family and friends: step-by-step quick start (ports, first login, 2FA), adding users and invites, which app to use on each platform, upgrade and rollback, several servers, the Telegram bot, and troubleshooting (blocked ports, certificates, traffic, AI check, lost password or 2FA).

**Performance** (measured with 500 accounts and a year of daily traffic)
- Shared quota is worked out from the account's own invite chain instead of loading every account: a subscription download is 7–19× faster, the member page about 10× faster.
- The admin panel refresh (`/api/state`), the once-a-minute quota/expiry check and `/expiring` build the invite index once instead of once per account (was O(n²)); the panel refresh no longer starts `openssl` each time to read the certificate names (cached until the file changes).
- Traffic readings are written in one batched statement, and lookups that only need ids or names no longer load full account rows.

**Installer**
- RHEL/Rocky/Alma 8 and openSUSE Leap 15, whose `python3` is 3.6, get a newer Python installed next to it; the panel service, the `vps2vpn` command and `restore.sh` run on the Python the installer chose.
- apt waits up to 5 minutes for the dpkg lock (unattended-upgrades on a VPS's first boot) instead of failing, keeps locally changed config files without asking, and never stops at needrestart's dialog.
- The installer's error messages are visible again: taking the install lock used to send every later error to `/dev/null`, so a failing install ended without a word. A failed package install says so too.
- `vps2vpn init` no longer crashes (and fails the install) on a system without `modprobe`, `sysctl` or `ss`; the installer also adds `kmod`, `procps`, `iproute2`, `findutils` and `useradd` where a minimal image lacks them.
- Debian 11 is past its end of life and its updates moved to archive.debian.org: when apt gets 404s there, the installer adds the archive as a package source once and retries.
- systemd older than 245 (RHEL/Rocky/Alma 8) no longer logs `ProtectClock` / `ProtectKernelLogs` as unknown settings in the units.
- An IPv6-only server that cannot download from GitHub is told why and what to do.

**CI**
- New `install-distros` job: the real `install.sh` in systemd containers of Debian 11/12, Ubuntu 20.04/22.04/24.04, AlmaLinux 9 and Rocky Linux 8 — fresh install, the panel answers on its port, the cores run unprivileged, an upgrade takes a snapshot and keeps the database, rollback, uninstall and reinstall (`tests/container_install.sh`, also runnable locally with Docker).

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
