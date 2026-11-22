#!/bin/bash
# vps2vpn one-click deploy for macOS and Linux. Double-click it in Finder (or run: bash deploy-mac.command).
cd "$(dirname "$0")" || exit 1
set -u

# Python is there (Linux; Mac with the developer tools): use the full deployer page in the browser
# (firewall check, VPN app import, adding a second server). The macOS python3 stub would pop up an
# install dialog, so on a Mac only use it when the developer tools are really installed.
if command -v python3 >/dev/null 2>&1 && { [ "$(uname)" != Darwin ] || xcode-select -p >/dev/null 2>&1; } \
   && python3 -c 'import ssl, http.server' >/dev/null 2>&1; then
  echo "vps2vpn 一键部署：浏览器里会打开部署页面。用完关掉这个窗口即可。"
  exec python3 deploy/deploy.py
fi

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
safe_url() {
  local u="$1" re="$2"
  [ -n "$u" ] || return 1
  [[ "$u" != -* ]] || return 1
  [[ "$u" != *[[:space:][:cntrl:]]* ]] || return 1
  [[ "$u" =~ $re ]]
}

say "vps2vpn 一键部署 / one-click deploy"
read -r -p "服务器 IP / server IP: " HOST
HOST=$(printf '%s' "$HOST" | tr -d '[] ')
if ! [[ "$HOST" =~ ^[A-Za-z0-9.:-]{3,255}$ ]] || [[ "$HOST" == -* ]]; then
  echo "IP 地址格式不对 / invalid server IP: $HOST"; exit 1
fi
echo
echo "把 SSH 密钥文件（.pem / id_ed25519）拖进这个窗口然后按回车；没有密钥就直接按回车，稍后输入密码。"
echo "Drag your SSH key file into this window and press Enter; no key? just press Enter and type the password later."
read -r -p "> " KEY
KEY=$(printf '%s' "$KEY" | sed -e "s/^ *//" -e "s/ *$//" -e "s/^'//" -e "s/'$//" -e 's/\\ / /g')
if [ -n "$KEY" ] && [ -d "$KEY" ]; then
  for n in id_ed25519 id_ecdsa id_rsa; do [ -f "$KEY/$n" ] && KEY="$KEY/$n" && break; done
fi
USER_DEF=root
case "$KEY" in *[Ll]ightsail*|*.pem) USER_DEF=ubuntu ;; esac
read -r -p "登录用户名 / login user [$USER_DEF]: " LUSER
LUSER=${LUSER:-$USER_DEF}
if ! [[ "$LUSER" =~ ^[a-z_][a-z0-9_.-]{0,31}$ ]]; then
  echo "用户名格式不对 / invalid user: $LUSER"; exit 1
fi
read -r -p "SSH 端口 / port [22]: " PORT
PORT=${PORT:-22}
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
  echo "SSH 端口不对 / invalid port: $PORT"; exit 1
fi
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
# Server keys are remembered next to the saved logins (the same file deploy.py uses), so a server whose key
# changed since the last deploy is refused instead of trusted again. ssh splits this value on spaces and
# expands %-tokens in it: quote it and double every %.
REC_DIR="$HOME/vps2vpn"; mkdir -p "$REC_DIR" || exit 1; chmod 700 "$REC_DIR"
KH="$REC_DIR/known_hosts"
KH_NAME="$HOST"; [ "$PORT" = 22 ] || KH_NAME="[$HOST]:$PORT"
OPTS=(-F none -p "$PORT" -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=\"${KH//\%/%%}\""
      -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=8)
if [ -n "$KEY" ]; then
  [ -f "$KEY" ] || { echo "找不到这个文件 / file not found: $KEY"; exit 1; }
  cp "$KEY" "$WORK/key" && chmod 600 "$WORK/key"
  OPTS+=(-i "$WORK/key" -o IdentitiesOnly=yes)
fi
RUNAS=""; [ "$LUSER" = root ] || RUNAS="sudo -n env "
say "打包并上传，然后在服务器上安装（1-3 分钟）/ uploading and installing (1-3 minutes)"
tar -czf "$WORK/v.tgz" --exclude=__pycache__ --exclude='*.pyc' install.sh vps2vpn || exit 1
base64 < "$WORK/v.tgz" | tr -d '\n' > "$WORK/v.b64"; echo >> "$WORK/v.b64"
REMOTE='set -e; T=$(mktemp -d); trap '\''rm -rf "$T"'\'' EXIT; base64 -d > "$T/v.tgz"; tar -xzf "$T/v.tgz" -C "$T"; '"$RUNAS"'V2V_AUTO=1 V2V_SRC="$T/v.tgz" bash "$T/install.sh" install'
# the result line holds the new admin password: keep it out of the window
ssh "${OPTS[@]}" -- "$LUSER@$HOST" "$REMOTE" < "$WORK/v.b64" | tee "$WORK/log" | grep -v '^V2V_RESULT:'
rc=${PIPESTATUS[0]}
B64=$(grep '^V2V_RESULT:' "$WORK/log" | tail -1 | cut -d: -f2 | tr -d '\r\n ')
rm -f "$WORK/log"
if [ "$rc" -ne 0 ] || [ -z "$B64" ]; then
  say "出错了 / something went wrong (exit $rc)."
  echo "Permission denied -> 密钥/密码/用户名不对（亚马逊一般是 ubuntu / ec2-user / admin）"
  echo "timed out / refused -> IP 写错、服务器没开机，或云厂商防火墙没放行 SSH 端口"
  echo "Host key verification failed -> 服务器身份和上次不一样。刚重装过系统就运行  ssh-keygen -R '$KH_NAME' -f '$KH'  再部署；没重装过先别继续，可能有人冒充你的服务器"
  read -r -p "按回车关闭 / press Enter to close" _
  exit 1
fi

# Save the login next to the other servers (only on this computer), keeping an older password on upgrades.
REC="$REC_DIR/$(printf '%s' "$HOST" | tr -c 'A-Za-z0-9._-' '_').json"
JSON=$(printf '%s' "$B64" | base64 -d 2>/dev/null || printf '%s' "$B64" | base64 -D)
OLD="{}"; [ -f "$REC" ] && OLD=$(cat "$REC")
# osascript's JavaScript reads JSON on every Mac without extra software; pass data via env vars (never argv)
read_json() {
  V2V_JSON="$1" V2V_EXPR="$2" osascript -l JavaScript -e '
    ObjC.import("Foundation");
    function env(k){var v=$.NSProcessInfo.processInfo.environment.objectForKey(k);return v?ObjC.unwrap(v):""}
    function run(){var r=JSON.parse(env("V2V_JSON"));var v=eval("r"+env("V2V_EXPR"));return v===undefined||v===null?"":(typeof v==="object"?JSON.stringify(v):String(v))}
  ' 2>/dev/null
}
MERGED=$(V2V_OLD="$OLD" V2V_JSON="$JSON" V2V_HOST="$HOST" V2V_USER="$LUSER" V2V_PORT="$PORT" osascript -l JavaScript -e '
  ObjC.import("Foundation");
  function env(k){var v=$.NSProcessInfo.processInfo.environment.objectForKey(k);return v?ObjC.unwrap(v):""}
  function run(){
    var o=JSON.parse(env("V2V_OLD")),r=JSON.parse(env("V2V_JSON")),x=r.auto||{};
    ["panel","pin","join_code","name","user","sub_url","qr_url","links","checks","ai"].forEach(function(k){if(x[k]!=null)o[k]=x[k]});
    if(x.admin_password){o.admin_user=x.admin_user;o.admin_password=x.admin_password}
    o.host=env("V2V_HOST");o.ssh_user=env("V2V_USER");o.ssh_port=+env("V2V_PORT");o.cloud=r.cloud||"";o.cloud_firewall=r.cloud_firewall||"";
    o.updated=new Date().toISOString().slice(0,16).replace("T"," ");o["说明"]="vps2vpn 一键部署工具保存的登录信息。只在你自己的电脑上，不要发给别人。";
    return JSON.stringify(o,null,2)
  }
' 2>/dev/null)
if [ -n "$MERGED" ]; then (umask 077; printf '%s\n' "$MERGED" > "$REC")
else (umask 077; printf '%s\n' "$JSON" > "$REC"); echo "登录信息保存在 $REC"; MERGED="$OLD"; fi

PANEL=$(read_json "$MERGED" .panel)
SUB=$(read_json "$MERGED" .sub_url)
V2V_LINK=$(read_json "$MERGED" .links.vps2vpn)
CLASH=$(read_json "$MERGED" .links.clash)
PW=$(read_json "$MERGED" .admin_password)
say "部署成功 / Done!"
AI=$(read_json "$MERGED" .ai.summary)
if [ -n "$AI" ]; then
  echo
  echo "AI 可用性（从服务器测试）：$AI"
  echo "  $(read_json "$MERGED" .ai.place) · $(read_json "$MERGED" .ai.org) · $(read_json "$MERGED" .ai.kind)"
  read_json "$MERGED" '.ai.advice.join(String.fromCharCode(10))' | sed 's/^/  /'
fi

echo
echo "防火墙检查（从这台电脑测试 TCP 端口）："
BAD=0
CHECKED=0
while IFS= read -r p; do
  if ! [[ "$p" =~ ^[0-9]+$ ]] || [ "$p" -lt 1 ] || [ "$p" -gt 65535 ]; then continue; fi
  CHECKED=1
  if nc -z -G 5 "$HOST" "$p" >/dev/null 2>&1 || nc -z -w 5 "$HOST" "$p" >/dev/null 2>&1; then echo "  ✓ TCP $p 通了"; else echo "  ✗ TCP $p 不通"; BAD=1; fi
done < <(read_json "$MERGED" '.checks.filter(function(c){return c[0]=="tcp"}).map(function(c){return c[1]}).join(String.fromCharCode(10))')
[ "$CHECKED" = 1 ] || BAD=1
if [ "$BAD" = 1 ]; then
  echo "  有端口被云服务商的防火墙挡住了。$(read_json "$MERGED" .cloud_firewall)"
  echo "  请到云服务商控制台的「防火墙 / 安全组」放行：协议选「全部」，来源 0.0.0.0/0。"
fi

APP=""
for a in vps2vpn "Clash Verge" FlClash "Mihomo Party" "Clash Nyanpasu" "ClashX Meta" ClashX Stash; do
  [ -d "/Applications/$a.app" ] || [ -d "$HOME/Applications/$a.app" ] && { APP="$a"; break; }
done
IMPORT_URL="$CLASH"
if [ "$APP" = "vps2vpn" ] && [ -n "$V2V_LINK" ]; then IMPORT_URL="$V2V_LINK"; fi
echo
if [ -n "$APP" ] && safe_url "$IMPORT_URL" '^(vps2vpn|clash|hiddify|sing-box)://' && [ "$BAD" = 0 ]; then
  echo "检测到你电脑上的 $APP，已经自动打开它导入。在它弹出的窗口点「确定/导入」，再打开「系统代理」开关就能用了。"
  echo "分流规则（国内网站直连、国外走代理）已经写好，不用自己设置。"
  open -- "$IMPORT_URL" 2>/dev/null
elif safe_url "$SUB" '^https?://[^/]+'; then
  echo "没检测到 VPN 软件（或者防火墙还没放行）。推荐装免费开源的 Clash Verge Rev："
  echo "  https://github.com/clash-verge-rev/clash-verge-rev/releases/latest"
  echo "装好后把下面的订阅链接粘贴到软件的「新建订阅」里。浏览器里会打开订阅页，手机可以扫上面的二维码导入。"
  echo "  $SUB"
  # xdg-open takes no options (it rejects "--"); safe_url already refused a URL starting with "-".
  # Only a Mac's open: on Debian "open" is openvt.
  if [ "$(uname)" = Darwin ]; then open -- "$SUB" 2>/dev/null
  elif command -v xdg-open >/dev/null; then xdg-open "$SUB" >/dev/null 2>&1; fi
fi
echo
echo "管理面板（加用户、看流量）：$PANEL"
if [ -n "$PW" ]; then
  echo "用户名 admin，密码已复制到剪贴板（也保存在 $REC，只在你的电脑上）。"
  command -v pbcopy >/dev/null && printf '%s' "$PW" | pbcopy
else
  echo "用户名和密码：用你自己设置的那个。"
fi
echo "浏览器若提示「不安全」，点「高级 → 继续访问」即可（照样加密）。"
read -r -p "按回车关闭 / press Enter to close" _
