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

# What a beginner pastes into the IP prompt -> HOST, T_USER, T_PORT (same as parse_target() in deploy.py):
# "203.0.113.10:22", "root@203.0.113.10", "[v6]:2222", a whole "ssh -i key.pem -p 2222 ubuntu@203.0.113.10" from a cloud
# console, http://203.0.113.10/, and dots or digits typed by a Chinese input method (。．１２３).
# Written for the bash 3.2 macOS ships with: no ${x,,}, and no "${W[@]}" of an empty array under set -u.
parse_target() {
  local t="$1" n dest="" u w i q c len have W WN re6='^\[([0-9A-Fa-f:.]+)\](:([0-9]+))?$' re4='^([^:]*):([0-9]*)$'
  T_USER=""; T_PORT=""
  n=$(printf '%s' "$t" | perl -CS -MUnicode::Normalize -pe '$_ = NFKC($_); s/\x{3002}|\x{FF61}/./g' 2>/dev/null) && t="$n"
  t="${t#"${t%%[![:space:]]*}"}"; t="${t%"${t##*[![:space:]]}"}"
  q="${t:0:1}"                                   # the whole paste in one pair of quotes: what is inside
  if [ ${#t} -ge 2 ] && { [ "$q" = '"' ] || [ "$q" = "'" ]; } && [ "${t:${#t}-1:1}" = "$q" ]; then
    w="${t:1:${#t}-2}"
    case "$w" in *"$q"*) ;; *) t="${w#"${w%%[![:space:]]*}"}"; t="${t%"${t##*[![:space:]]}"}" ;; esac
  fi
  w=$(printf '%s' "${t%%[[:space:]]*}" | tr 'A-Z' 'a-z')
  if [ "$w" = ssh ] || [ "$w" = ssh.exe ]; then  # SSH, or ssh.exe copied from Windows
    # its words as a shell splits them, in W[0..WN-1]: -i "My Key.pem" is one word, and -p "2222" or
    # "ubuntu@203.0.113.10" keep what is inside the quotes (the old sed turned every quoted word into x)
    W=(); WN=0; i=0; len=${#t}; q=""; w=""; have=0
    while [ $i -lt $len ]; do
      c="${t:i:1}"
      if [ "$q" = "'" ]; then
        if [ "$c" = "'" ]; then q=""; else w="$w$c"; fi
      elif [ "$q" = '"' ]; then
        if [ "$c" = '"' ]; then q=""
        elif [ "$c" = '\' ] && [ $((i + 1)) -lt $len ] && { [ "${t:i+1:1}" = '"' ] || [ "${t:i+1:1}" = '\' ]; }; then
          i=$((i + 1)); w="$w${t:i:1}"
        else w="$w$c"; fi
      else
        case "$c" in
          ' '|$'\t'|$'\n') if [ $have = 1 ]; then W[WN]="$w"; WN=$((WN + 1)); w=""; have=0; fi ;;
          '"'|"'") q="$c"; have=1 ;;
          '\') if [ $((i + 1)) -lt $len ]; then i=$((i + 1)); w="$w${t:i:1}"; fi; have=1 ;;
          *) w="$w$c"; have=1 ;;
        esac
      fi
      i=$((i + 1))
    done
    if [ $have = 1 ]; then W[WN]="$w"; WN=$((WN + 1)); fi
    if [ -n "$q" ]; then read -r -a W <<< "$t"; WN=${#W[@]}; fi      # an unclosed quote: plain words
    i=1
    while [ $i -lt $WN ]; do
      w="${W[i]}"
      case "$w" in
        -p|-l) if [ $((i + 1)) -lt $WN ]; then
                 i=$((i + 1)); if [ "$w" = -p ]; then T_PORT="${W[i]}"; else T_USER="${W[i]}"; fi
               fi ;;
        -p*) case "${w#-p}" in *[!0-9]*) ;; *) T_PORT="${w#-p}" ;; esac ;;    # -p2222, not -p2222abc
        -i|-o|-F|-J|-L|-R|-D|-b|-c|-m|-E|-W) i=$((i + 1)) ;;               # an option with a value: skip both
        -*) ;;
        *) [ -n "$dest" ] || dest="$w" ;;
      esac
      i=$((i + 1))
    done
    t="$dest"
  fi
  # quotes around what is left are not part of it ("203.0.113.10", 'root@203.0.113.10'), as in deploy.py
  while :; do case "$t" in \"*|\'*) t="${t:1}" ;; *\"|*\') t="${t%?}" ;; *) break ;; esac; done
  set -f; set -- $t; set +f
  if [ $# -gt 1 ]; then
    t=""
  else
    t="${1:-}"
  fi
  t="${t#*://}"; t="${t%%/*}"
  case "$t" in *@*) u="${t%@*}"; t="${t##*@}"; [ -n "$T_USER" ] || T_USER=$(printf '%s' "$u" | tr 'A-Z' 'a-z') ;; esac
  if [[ "$t" =~ $re6 ]]; then t="${BASH_REMATCH[1]}"; [ -z "${BASH_REMATCH[3]}" ] || T_PORT="${BASH_REMATCH[3]}"
  elif [[ "$t" =~ $re4 ]]; then t="${BASH_REMATCH[1]}"; [ -z "${BASH_REMATCH[2]}" ] || T_PORT="${BASH_REMATCH[2]}"; fi
  HOST="$t"
}

say "vps2vpn 一键部署 / one-click deploy"
while :; do
  read -r -p "服务器 IP / server IP: " HOST || exit 1
  parse_target "$HOST"
  if [[ "$HOST" =~ ^[A-Za-z0-9.:-]{3,255}$ ]] && [[ "$HOST" != -* ]]; then break; fi
  echo "IP 地址格式不对：只填服务器的 IP（例如 203.0.113.10）或域名。请再输入一次。/ Type just the server's IP or name."
done
[ -z "$T_USER$T_PORT" ] || echo "服务器 $HOST，用户名 ${T_USER:-（下面再问）}，端口 ${T_PORT:-22}"
echo
echo "把 SSH 密钥文件（.pem / id_ed25519）拖进这个窗口然后按回车；没有密钥就直接按回车，稍后输入密码。"
echo "Drag your SSH key file into this window and press Enter; no key? just press Enter and type the password later."
read -r -p "> " KEY
KEY=$(printf '%s' "$KEY" | sed -e "s/^ *//" -e "s/ *$//" -e "s/^'//" -e "s/'$//" -e 's/\\ / /g')
if [ -n "$KEY" ] && [ -d "$KEY" ]; then
  for n in id_ed25519 id_ecdsa id_rsa; do [ -f "$KEY/$n" ] && KEY="$KEY/$n" && break; done
fi
USER_DEF=root
# AWS key names only: a .pem from another cloud usually logs in as root
case "$(basename "$KEY")" in *[Ll]ightsail*|*[Ee][Cc]2*|*[Aa][Ww][Ss]*) USER_DEF=ubuntu ;; esac
[ -z "$T_USER" ] || USER_DEF="$T_USER"
read -r -p "登录用户名 / login user [$USER_DEF]: " LUSER
LUSER=${LUSER:-$USER_DEF}
if ! [[ "$LUSER" =~ ^[a-z_][a-z0-9_.-]{0,31}$ ]]; then
  echo "用户名格式不对 / invalid user: $LUSER"; exit 1
fi
PORT_DEF=${T_PORT:-22}
read -r -p "SSH 端口 / port [$PORT_DEF]: " PORT
PORT=${PORT:-$PORT_DEF}
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
  # a key saved on Windows may have CRLF line ends, which ssh rejects
  (umask 077; tr -d '\r' < "$KEY" > "$WORK/key") || exit 1
  if head -c 20 "$WORK/key" | grep -q '^PuTTY-User-Key-File'; then
    echo "这是 PuTTY 格式的密钥（.ppk），ssh 不能直接用：先用 puttygen 转成 OpenSSH 格式再拖进来。"
    echo "This is a PuTTY .ppk key; convert it first:  puttygen key.ppk -O private-openssh -o key.pem"; exit 1
  fi
  if ! grep -q 'PRIVATE KEY' "$WORK/key"; then
    echo "这不是私钥文件（.pub 是公钥，要用不带 .pub 的那个）/ not a private key file"; exit 1
  fi
  if grep -q 'ENCRYPTED' "$WORK/key" || ! ssh-keygen -y -P '' -f "$WORK/key" >/dev/null 2>&1; then
    echo "这个私钥设了密码保护或已损坏：换一个没有密码的密钥，或先复制一份再运行  ssh-keygen -p -f 复制出的文件  去掉密码。"
    echo "This key is passphrase-protected (or damaged); use a key without a passphrase."; exit 1
  fi
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
# cloud images (AWS and others) answer root logins with: Please login as the user "ubuntu" rather than ...
WANT=$(grep -o 'login as the user "[a-z_][a-z0-9_.-]*"' "$WORK/log" | head -1 | cut -d'"' -f2)
rm -f "$WORK/log"
if [ "$rc" -ne 0 ] || [ -z "$B64" ]; then
  say "出错了 / something went wrong (exit $rc)."
  if [ -n "$WANT" ] && [ "$WANT" != "$LUSER" ]; then
    echo "-> 服务器要求用 $WANT 登录：重新运行，用户名填 $WANT / log in as \"$WANT\" instead of \"$LUSER\""
  fi
  echo "Permission denied -> 密钥/密码/用户名不对（亚马逊一般是 ubuntu / ec2-user / admin）"
  echo "timed out / refused -> IP 写错、服务器没开机，或云厂商防火墙没放行 SSH 端口"
  echo "Connection closed / reset -> SSH 端口不对、服务器刚开机（等一两分钟），或这台电脑开着 VPN / 代理（尤其是 TUN 模式），先关掉再试"
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
say "服务器上装好了 / Installed on the server"
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
  echo "  ⚠️ 还差这一步：放行之前 VPN 连不上。放行后在 VPN 软件里导入下面的订阅链接即可，不用重新部署。"
else
  echo "  全部通了 ✓"
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
  if [ -n "$APP" ]; then
    echo "检测到你电脑上的 $APP。防火墙放行后，把下面的订阅链接粘贴到它的「新建订阅 / 导入」里。"
  else
    echo "没检测到 VPN 软件。推荐装免费开源的 Clash Verge Rev："
    echo "  https://github.com/clash-verge-rev/clash-verge-rev/releases/latest"
    echo "装好后把下面的订阅链接粘贴到软件的「新建订阅」里。"
  fi
  echo "  $SUB"
  echo "浏览器里会打开订阅页，手机扫那个页面上的二维码就能导入。"
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
echo
echo "接下来可以做什么："
echo "  · 给家人朋友开账号：打开管理面板 →「使用者」添加，每人有自己的订阅链接、流量和到期时间。"
echo "  · 再加一台服务器：在管理面板 →「多服务器」里操作（Mac 上装了 Python 时，部署工具可以自动加入）。"
echo "  · 以后想升级：再运行一次这个部署工具、填同一个 IP 就行，账号和设置都会保留。"
read -r -p "按回车关闭 / press Enter to close" _
