#!/usr/bin/env bash
# vps2vpn installer - turns a fresh Linux VPS into a private VPN server with a web panel.
#
#   bash install.sh            install, or upgrade an existing install (keeps users and settings)
#   bash install.sh info       show the panel link again
#   bash install.sh uninstall  remove everything vps2vpn added
#
# Without a checkout next to it, the panel code is the latest tagged release, checked against the
# release's SHA256 file before anything is unpacked. Developers can opt in to an unverified branch:
#   V2V_REF=main bash install.sh
# Every upgrade first snapshots the database and the previous code (last 3 kept) and prints how to roll back.
#
# Supported: Debian 11+, Ubuntu 20.04+, RHEL/Rocky/Alma/CentOS Stream 8+, Fedora, openSUSE, Arch; x86_64 and arm64.
set -euo pipefail

XRAY_VERSION="v26.3.27"   # v26.10.21+ rejects REALITY logins from mihomo 1.19 / sing-box 1.14 (tested 2026-11-18)
HYSTERIA_VERSION="app/v2.14.0"
SINGBOX_VERSION="v1.14.4"   # TUIC v5 server; release hashes pinned below (sing-box publishes no checksum file)
SINGBOX_SHA256_amd64="699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968"
SINGBOX_SHA256_arm64="436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26"
REPO="${V2V_REPO:-xydadada/vps2vpn}"          # where the panel code is downloaded from when not run from a checkout
PINNED_TAG="v0.2.39"   # release used when GitHub's API cannot be reached; bump it with every release
REF="${V2V_REF:-${V2V_BRANCH:-}}"   # development only: install this branch/tag/commit instead, UNVERIFIED
LIB=/usr/local/lib/vps2vpn
ETC=/etc/vps2vpn
VAR=/var/lib/vps2vpn
SNAPS="$VAR/upgrade-snapshots"     # database + code saved before each upgrade (root only, last 3 kept)
SNAPSHOT=""                         # the one made by this run
PY=python3                          # the Python 3.8+ the panel runs on (pick_python)

c_ok=$'\e[32m'; c_bad=$'\e[31m'; c_dim=$'\e[2m'; c_b=$'\e[1m'; c_0=$'\e[0m'
say()  { echo "${c_b}==>${c_0} $*"; }
die()  { echo "${c_bad}error:${c_0} $*" >&2; exit 1; }

_TMPDIRS=()
_cleanup() { if [ "${#_TMPDIRS[@]}" -gt 0 ]; then rm -rf -- "${_TMPDIRS[@]}"; fi; }
trap _cleanup EXIT                 # die() exits from inside functions: never leave downloads in /tmp

selinux_on() { command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; }

# Best effort: give files the SELinux type systemd may execute / swapon may use. Never fails the install.
selinux_label() {  # type path...
  local t="$1"; shift
  selinux_on || return 0
  if command -v semanage >/dev/null 2>&1; then
    local f
    for f in "$@"; do
      semanage fcontext -a -t "$t" "$f" 2>/dev/null || semanage fcontext -m -t "$t" "$f" 2>/dev/null || true
    done
  fi
  if command -v restorecon >/dev/null 2>&1; then restorecon -F "$@" 2>/dev/null || true; fi
  # without a persistent rule restorecon may have put the default type back: set it directly
  if command -v chcon >/dev/null 2>&1; then chcon -t "$t" "$@" 2>/dev/null || true; fi
}

need_root() {
  [ "$(id -u)" = 0 ] || die "please run as root, e.g.:  sudo bash install.sh
  需要 root 权限：先运行  sudo -i  切换成 root，再把安装命令重新粘贴一次。"
  [ "$(uname -s)" = Linux ] || die "Linux only"
  command -v systemctl >/dev/null || die "this system has no systemd"
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  XRAY_ASSET=Xray-linux-64.zip;          HY_ASSET=hysteria-linux-amd64; SB_ARCH=amd64 ;;
    aarch64|arm64) XRAY_ASSET=Xray-linux-arm64-v8a.zip;   HY_ASSET=hysteria-linux-arm64; SB_ARCH=arm64 ;;
    *) die "unsupported CPU: $(uname -m) (x86_64 and arm64 are supported)" ;;
  esac
}

APT_OPTS=(-o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)

python_ok() { "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; }

pick_python() {  # -> PY = absolute path of a Python 3.8+ (the distro's python3 first)
  local c p
  for c in python3 python3.13 python3.12 python3.11 python3.10 python3.9 python3.8; do
    p=$(command -v "$c" 2>/dev/null) || continue
    if python_ok "$p"; then PY="$p"; return 0; fi
  done
  return 1
}

debian_archive_sources() {  # -> 0 if an end-of-life Debian was given its archive.debian.org sources
  # Debian 11 left LTS in 2026: its security updates now live only on archive.debian.org, so
  # installing any package with a security update fails with 404 from the usual mirrors.
  local id code f="$APT_SOURCES/vps2vpn-debian-archive.list"
  [ -r "$OS_RELEASE" ] || return 1
  # shellcheck source=/dev/null
  id=$(. "$OS_RELEASE" && echo "${ID:-}")
  # shellcheck source=/dev/null
  code=$(. "$OS_RELEASE" && echo "${VERSION_CODENAME:-}")
  [ "$id" = debian ] && [ "$code" = bullseye ] && [ ! -e "$f" ] || return 1
  say "Debian 11 is past its end of life and its updates moved to archive.debian.org; adding it as a package source ($f) / Debian 11 已停止维护，改用存档软件源"
  printf 'deb [check-valid-until=no] http://archive.debian.org/%s main\n' \
    "debian $code" "debian $code-updates" "debian-security $code-security" > "$f" || return 1
  apt-get "${APT_OPTS[@]}" update -qq || true
}

install_packages() {
  local pkgs=(python3 openssl tar unzip nftables ca-certificates)
  command -v curl >/dev/null 2>&1 || pkgs+=(curl)     # RHEL ships curl-minimal, which conflicts with "curl"
  # tools a minimal image may lack (the panel runs modprobe/sysctl for BBR, ss for port owners)
  local tool deb rpm suse arch col
  if command -v apt-get >/dev/null; then col=2
  elif command -v dnf >/dev/null || command -v yum >/dev/null; then col=3
  elif command -v zypper >/dev/null; then col=4
  else col=5; fi
  while read -r tool deb rpm suse arch; do
    command -v "$tool" >/dev/null 2>&1 && continue
    case "$col" in 2) pkgs+=("$deb") ;; 3) pkgs+=("$rpm") ;; 4) pkgs+=("$suse") ;; *) pkgs+=("$arch") ;; esac
  done <<'EOF'
find findutils findutils findutils findutils
useradd passwd shadow-utils shadow shadow
modprobe kmod kmod kmod kmod
sysctl procps procps-ng procps procps-ng
ss iproute2 iproute iproute2 iproute2
EOF
  say "installing system packages / 正在安装系统软件包"
  local failed="could not install the system packages (${pkgs[*]}); the package manager's message is above"
  if command -v apt-get >/dev/null; then
    # a fresh VPS often runs unattended-upgrades on first boot: wait for its dpkg lock instead of failing,
    # keep locally changed config files without asking, and never stop at needrestart's service dialog
    export DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 NEEDRESTART_MODE=l
    apt-get "${APT_OPTS[@]}" update -qq || true
    apt-get "${APT_OPTS[@]}" install -y -qq "${pkgs[@]}" >/dev/null \
      || { debian_archive_sources && apt-get "${APT_OPTS[@]}" install -y -qq "${pkgs[@]}" >/dev/null; } \
      || die "$failed"
  elif command -v dnf >/dev/null; then dnf install -y -q "${pkgs[@]}" >/dev/null || die "$failed"
  elif command -v yum >/dev/null; then yum install -y -q "${pkgs[@]}" >/dev/null || die "$failed"
  elif command -v zypper >/dev/null; then zypper -nq install "${pkgs[@]}" >/dev/null || die "$failed"
  elif command -v pacman >/dev/null; then
    local pac=(python "${pkgs[@]:1}")       # Arch calls python3 "python"
    pacman -Sy --noconfirm --needed "${pac[@]}" >/dev/null || die "$failed"
  else die "unknown package manager; install: ${pkgs[*]}"; fi
  if ! pick_python; then
    # RHEL/Rocky/Alma 8 and openSUSE Leap 15 ship Python 3.6 as python3: add a newer one next to it
    say "$(python3 --version 2>&1 || echo 'no python3') is too old; installing a newer Python next to it / Python 版本太旧，正在另装一个新版"
    local p
    for p in python3.12 python3.11 python39 python311 python312; do
      if command -v dnf >/dev/null; then dnf install -y -q "$p" >/dev/null 2>&1 || continue
      elif command -v yum >/dev/null; then yum install -y -q "$p" >/dev/null 2>&1 || continue
      elif command -v zypper >/dev/null; then zypper -nq install "$p" >/dev/null 2>&1 || continue
      else break; fi
      pick_python && break
    done
    pick_python || die "python 3.8 or newer is required (found: $(python3 --version 2>&1 || echo none))"
  fi
  say "using $("$PY" --version 2>&1) ($PY) / 使用这个 Python"
}

ROUTE4=/proc/net/route
LOCK=/run/vps2vpn-install.lock
OS_RELEASE=/etc/os-release
APT_SOURCES=/etc/apt/sources.list.d
no_ipv4() {  # -> 0 if this machine has no IPv4 default route (an IPv6-only VPS)
  [ -r "$ROUTE4" ] || return 1
  ! awk 'NR > 1 && $2 == "00000000" {f = 1} END {exit !f}' "$ROUTE4"
}

fetch() {  # url dest
  curl -fL --retry 3 --connect-timeout 15 -sS -o "$2" "$1" && return 0
  if no_ipv4; then
    die "download failed: $1
  This server has no IPv4, and GitHub cannot be reached over IPv6 alone. Give it IPv4 for outgoing
  connections first (NAT64/DNS64 from your provider or a public NAT64 resolver, or Cloudflare WARP),
  then run the installer again. / 这台服务器只有 IPv6，访问不了 GitHub：先配好 NAT64/DNS64 或 WARP 再装。"
  fi
  die "download failed: $1
  下载失败：服务器暂时连不上 GitHub。过几分钟再运行一次安装命令；一直不行就检查服务器能否上网（curl -I https://github.com）。"
}

try_fetch() {  # url dest -> non-zero instead of dying (a file that may not exist, e.g. a release asset)
  rm -f "$2"
  curl -fL --retry 3 --connect-timeout 15 -sS -o "$2" "$1" 2>/dev/null
}

warn() { echo "${c_bad}warning:${c_0} $*" >&2; }

pkg_version() {  # path/to/vps2vpn/__init__.py -> its VERSION, or nothing
  [ -f "$1" ] || return 0
  sed -n "s/^VERSION = ['\"]\([^'\"]*\)['\"].*/\1/p" "$1" | head -1
}

version_lt() {  # a b -> 0 if version a is older than b
  "$PY" -c 'import re, sys
v = lambda s: tuple(int(x) for x in re.findall(r"[0-9]+", s))
sys.exit(0 if v(sys.argv[1]) < v(sys.argv[2]) else 1)' "$1" "$2"
}

latest_release_tag() {  # -> tag of the newest published release, or nothing if GitHub's API cannot be reached
  curl -fsS --connect-timeout 10 --max-time 20 -H 'Accept: application/vnd.github+json' \
    "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null | "$PY" -c 'import json, re, sys
t = json.load(sys.stdin).get("tag_name") or ""
print(t if re.match(r"^v[0-9][0-9A-Za-z._-]*$", t) else "")' 2>/dev/null || true
}

fetch_panel_code() {  # tmp -> panel code unpacked under tmp (tmp/vps2vpn)
  local tmp="$1" tag name want got
  if [ -n "$REF" ]; then
    [[ "$REF" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] || die "V2V_REF is not a branch, tag or commit: $REF"
    warn "UNVERIFIED development install: panel code from '$REF' of github.com/$REPO, no checksum"
    fetch "https://github.com/$REPO/archive/$REF.tar.gz" "$tmp/src.tgz"
  else
    tag=$(latest_release_tag)
    if [ -z "$tag" ]; then
      tag="$PINNED_TAG"
      say "GitHub's API is unreachable; using the pinned release $tag / 连不上 GitHub 接口，改用内置版本 $tag"
    fi
    name="vps2vpn-$tag.tar.gz"
    say "downloading vps2vpn $tag from github.com/$REPO/releases / 正在下载 vps2vpn $tag"
    if try_fetch "https://github.com/$REPO/releases/download/$tag/$name" "$tmp/src.tgz"; then
      # a release that has the tarball must have its checksum too, and it must match
      fetch "https://github.com/$REPO/releases/download/$tag/$name.sha256" "$tmp/src.tgz.sha256"
      want=$(awk -v f="$name" '{n=$2; sub(/^\*/, "", n); if (NF == 1 || n == f) {print $1; exit}}' "$tmp/src.tgz.sha256")
      got=$(sha256sum "$tmp/src.tgz" | awk '{print $1}')
      [ -n "$want" ] && [ "$want" = "$got" ] \
        || die "vps2vpn $tag checksum mismatch (expected ${want:-nothing}, got $got): refusing to install it"
      say "checksum OK: $got / 文件校验通过"
    elif try_fetch "https://github.com/$REPO/archive/refs/tags/$tag.tar.gz" "$tmp/src.tgz"; then
      # releases made before the release workflow existed carry no tarball: use GitHub's archive of the same tag
      warn "release $tag has no $name; installing GitHub's archive of tag $tag, UNVERIFIED (no checksum)"
    else
      warn "release $tag cannot be downloaded; installing the main branch, UNVERIFIED (no checksum)"
      fetch "https://github.com/$REPO/archive/refs/heads/main.tar.gz" "$tmp/src.tgz"
      tag=""
    fi
  fi
  tar --no-same-owner --no-same-permissions -xzf "$tmp/src.tgz" -C "$tmp" --strip-components=1
  if [ -z "$REF" ] && [ -n "$tag" ] && [ "${V2V_ALLOW_DOWNGRADE:-}" != 1 ]; then
    local have new
    have=$(pkg_version "$LIB/app/vps2vpn/__init__.py"); new=$(pkg_version "$tmp/vps2vpn/__init__.py")
    if [ -n "$have" ] && [ -n "$new" ] && version_lt "$new" "$have"; then
      die "the installed version $have is newer than release $tag ($new); not downgrading.
  To update to the development branch instead:  V2V_REF=main bash install.sh
  To downgrade anyway:                          V2V_ALLOW_DOWNGRADE=1 bash install.sh"
    fi
  fi
}

snapshot_before_upgrade() {  # -> SNAPSHOT=dir holding a consistent copy of the database and the current code
  local db="$VAR/vps2vpn.db"
  [ -d "$LIB/app/vps2vpn" ] || [ -f "$db" ] || return 0      # fresh install: nothing to keep
  local old stamp dir
  old=$(pkg_version "$LIB/app/vps2vpn/__init__.py")
  stamp=$(date -u +%Y%m%d-%H%M%S)
  dir="$SNAPS/$stamp-v${old:-unknown}"
  say "saving the current database and code to $dir / 正在备份当前的数据库和程序"
  (umask 077 && mkdir -p "$dir") || die "could not create $dir (disk full?); nothing was changed"
  chmod 0700 "$SNAPS" "$dir"
  if [ -f "$db" ]; then
    # SQLite's online backup: consistent even while the panel is writing (a plain copy of a WAL database is not)
    if ! (umask 077 && "$PY" -c 'import sqlite3, sys
src = sqlite3.connect(sys.argv[1], timeout=30)
dst = sqlite3.connect(sys.argv[2])
src.backup(dst)
ok = dst.execute("PRAGMA quick_check").fetchone()[0]
dst.close()
src.close()
sys.exit(0 if ok == "ok" else "snapshot check failed: " + ok)' "$db" "$dir/vps2vpn.db"); then
      rm -rf -- "$dir"
      die "could not snapshot the database (disk full?); nothing was changed"
    fi
  fi
  if [ -d "$LIB/app/vps2vpn" ]; then
    (umask 077 && tar -czf "$dir/app.tar.gz" --exclude=__pycache__ -C "$LIB/app" vps2vpn) \
      || { rm -rf -- "$dir"; die "could not snapshot the panel code (disk full?); nothing was changed"; }
  fi
  (umask 077 && cat > "$dir/restore.sh") <<EOF
#!/bin/bash
# Roll vps2vpn back to the snapshot taken $stamp UTC (version ${old:-unknown}): database and panel code.
set -euo pipefail
[ "\$(id -u)" = 0 ] || { echo "please run as root: sudo bash \$0" >&2; exit 1; }
S=\$(cd "\$(dirname "\$0")" && pwd)
systemctl stop vps2vpn 2>/dev/null || true
if [ -f "\$S/vps2vpn.db" ]; then
  install -m 0600 "\$S/vps2vpn.db" "$VAR/vps2vpn.db.restore"
  rm -f "$VAR/vps2vpn.db-wal" "$VAR/vps2vpn.db-shm"     # never replay the newer journal onto the old database
  mv -f "$VAR/vps2vpn.db.restore" "$VAR/vps2vpn.db"
fi
if [ -f "\$S/app.tar.gz" ]; then
  T=\$(mktemp -d); trap 'rm -rf "\$T"' EXIT
  tar --no-same-owner --no-same-permissions -xzf "\$S/app.tar.gz" -C "\$T"
  chown -R root:root "\$T/vps2vpn"
  find "\$T/vps2vpn" \\( -type d -exec chmod 0755 {} + \\) -o \\( -type f -exec chmod 0644 {} + \\)
  mkdir -p "$LIB/app"
  rm -rf "$LIB/app/vps2vpn.old"
  if [ -d "$LIB/app/vps2vpn" ]; then mv "$LIB/app/vps2vpn" "$LIB/app/vps2vpn.old"; fi
  mv "\$T/vps2vpn" "$LIB/app/vps2vpn"
fi
PYTHONPATH="$LIB/app" $PY -m vps2vpn apply --force >/dev/null 2>&1 || true
systemctl start vps2vpn
echo "vps2vpn is back to the snapshot of $stamp UTC (version ${old:-unknown})."
EOF
  # keep the newest 3 (names start with the UTC time, so the glob is in age order)
  local all=() d i
  for d in "$SNAPS"/[0-9]*-v*/; do if [ -d "$d" ]; then all+=("${d%/}"); fi; done
  for ((i = 0; i + 3 < ${#all[@]}; i++)); do rm -rf -- "${all[$i]}"; done
  SNAPSHOT="$dir"
  say "to roll back this upgrade later / 以后想退回这次升级:  sudo bash $SNAPSHOT/restore.sh"
}

install_cores() {
  local tmp; tmp=$(mktemp -d)
  _TMPDIRS+=("$tmp")
  mkdir -p "$LIB"
  local have_x="" have_h="" have_s=""
  [ -f "$LIB/.xray-version" ] && have_x=$(cat "$LIB/.xray-version")
  [ -f "$LIB/.hysteria-version" ] && have_h=$(cat "$LIB/.hysteria-version")
  [ -f "$LIB/.sing-box-version" ] && have_s=$(cat "$LIB/.sing-box-version")

  if [ "$have_x" != "$XRAY_VERSION" ] || [ ! -x "$LIB/xray" ]; then
    say "downloading Xray $XRAY_VERSION / 正在下载 Xray 内核"
    local base="https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION"
    fetch "$base/$XRAY_ASSET" "$tmp/xray.zip"
    fetch "$base/$XRAY_ASSET.dgst" "$tmp/xray.dgst"
    local want got
    want=$(grep -i '^SHA2-256=' "$tmp/xray.dgst" | head -1 | awk '{print $2}')
    got=$(sha256sum "$tmp/xray.zip" | awk '{print $1}')
    [ -n "$want" ] && [ "$want" = "$got" ] || die "Xray checksum mismatch (expected $want, got $got)"
    unzip -qo "$tmp/xray.zip" xray geoip.dat geosite.dat -d "$tmp/x"
    install -m 0755 "$tmp/x/xray" "$LIB/xray.new" && mv -f "$LIB/xray.new" "$LIB/xray"
    install -m 0644 "$tmp/x/geoip.dat" "$LIB/geoip.dat"
    install -m 0644 "$tmp/x/geosite.dat" "$LIB/geosite.dat"
    echo "$XRAY_VERSION" > "$LIB/.xray-version"
  fi

  if [ "$have_h" != "$HYSTERIA_VERSION" ] || [ ! -x "$LIB/hysteria" ]; then
    say "downloading Hysteria $HYSTERIA_VERSION / 正在下载 Hysteria 内核"
    local base="https://github.com/apernet/hysteria/releases/download/$HYSTERIA_VERSION"
    fetch "$base/$HY_ASSET" "$tmp/hysteria"
    fetch "$base/hashes.txt" "$tmp/hashes.txt"
    local want got
    want=$(awk -v f="$HY_ASSET" '{n=$2; sub(/^.*\//, "", n); if (n == f) {print $1; exit}}' "$tmp/hashes.txt")
    got=$(sha256sum "$tmp/hysteria" | awk '{print $1}')
    [ -n "$want" ] && [ "$want" = "$got" ] || die "Hysteria checksum mismatch (expected $want, got $got)"
    install -m 0755 "$tmp/hysteria" "$LIB/hysteria.new" && mv -f "$LIB/hysteria.new" "$LIB/hysteria"
    echo "$HYSTERIA_VERSION" > "$LIB/.hysteria-version"
  fi

  if [ "$have_s" != "$SINGBOX_VERSION" ] || [ ! -x "$LIB/sing-box" ]; then
    say "downloading sing-box $SINGBOX_VERSION (TUIC) / 正在下载 sing-box 内核"
    local v=${SINGBOX_VERSION#v} want got
    fetch "https://github.com/SagerNet/sing-box/releases/download/$SINGBOX_VERSION/sing-box-$v-linux-$SB_ARCH.tar.gz" "$tmp/sb.tgz"
    case "$SB_ARCH" in amd64) want="$SINGBOX_SHA256_amd64" ;; arm64) want="$SINGBOX_SHA256_arm64" ;; *) want="" ;; esac
    got=$(sha256sum "$tmp/sb.tgz" | awk '{print $1}')
    [ -n "$want" ] && [ "$want" = "$got" ] || die "sing-box checksum mismatch (expected $want, got $got)"
    mkdir -p "$tmp/sb" && tar --no-same-owner --no-same-permissions -xzf "$tmp/sb.tgz" -C "$tmp/sb" --strip-components=1
    install -m 0755 "$tmp/sb/sing-box" "$LIB/sing-box.new" && mv -f "$LIB/sing-box.new" "$LIB/sing-box"
    echo "$SINGBOX_VERSION" > "$LIB/.sing-box-version"
  fi
  rm -rf "$tmp"
  selinux_label bin_t "$LIB/xray" "$LIB/hysteria" "$LIB/sing-box"
}

install_app() {
  # Only a real script file has code "next to it". Piped in (curl ... | bash) BASH_SOURCE is just "bash" and
  # dirname would be the current directory, so a stray ./vps2vpn there would replace the verified download.
  local here=/nonexistent
  if [ -f "${BASH_SOURCE[0]:-}" ]; then
    here=$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo /nonexistent)
  fi
  local tmp; tmp=$(mktemp -d)
  _TMPDIRS+=("$tmp")
  if [ -n "${V2V_SRC:-}" ] && [ -f "$V2V_SRC" ]; then
    say "using panel code from $V2V_SRC / 使用上传的面板程序"
    tar --no-same-owner --no-same-permissions -xzf "$V2V_SRC" -C "$tmp"
  elif [ -f "$here/vps2vpn/__init__.py" ]; then
    say "using panel code next to this script / 使用本地的面板程序"
    cp -r "$here/vps2vpn" "$tmp/"
  else
    fetch_panel_code "$tmp"
  fi
  [ -f "$tmp/vps2vpn/__init__.py" ] || die "panel code not found in the download"
  "$PY" -m compileall -q "$tmp/vps2vpn" >/dev/null || die "panel code does not compile with $("$PY" --version 2>&1)"
  snapshot_before_upgrade
  mkdir -p "$LIB/app"
  rm -rf "$LIB/app/vps2vpn.new"
  cp -r "$tmp/vps2vpn" "$LIB/app/vps2vpn.new"
  # code run as root must not be writable by whoever owned the checkout / tarball
  chown -R root:root "$LIB/app/vps2vpn.new"
  find "$LIB/app/vps2vpn.new" \( -type d -exec chmod 0755 {} + \) -o \( -type f -exec chmod 0644 {} + \)
  rm -rf "$LIB/app/vps2vpn.old"
  [ -d "$LIB/app/vps2vpn" ] && mv "$LIB/app/vps2vpn" "$LIB/app/vps2vpn.old"
  mv "$LIB/app/vps2vpn.new" "$LIB/app/vps2vpn"
  rm -rf "$tmp"
  cat > /usr/local/bin/vps2vpn <<EOF
#!/bin/sh
PYTHONPATH=$LIB/app exec $PY -m vps2vpn "\$@"
EOF
  chmod 0755 /usr/local/bin/vps2vpn
  selinux_label bin_t /usr/local/bin/vps2vpn
}

systemd_new_hardening() {  # -> unit lines only systemd 245+ knows (EL8 has 239 and would log them as unknown)
  local v
  v=$(systemctl --version 2>/dev/null | awk 'NR == 1 {print $2 + 0}') || v=0
  if [ "${v:-0}" -ge 245 ]; then printf 'ProtectClock=yes\nProtectKernelLogs=yes'; fi
}

install_units() {
  local NEW_HARDENING; NEW_HARDENING=$(systemd_new_hardening)
  id vps2vpn >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin vps2vpn 2>/dev/null \
    || useradd -r -M -s /sbin/nologin vps2vpn
  mkdir -p "$ETC" "$VAR"
  chown root:vps2vpn "$ETC"; chmod 0750 "$ETC"; chmod 0700 "$VAR"

  cat > /etc/systemd/system/vps2vpn.service <<EOF
[Unit]
Description=vps2vpn panel
After=network-online.target
Wants=network-online.target

[Service]
Environment=PYTHONPATH=$LIB/app PYTHONUNBUFFERED=1
ExecStart=$PY -m vps2vpn serve
Restart=always
RestartSec=3
TimeoutStopSec=15
LimitNOFILE=65536
PrivateTmp=yes
ProtectHome=yes
$NEW_HARDENING
RestrictRealtime=yes
LockPersonality=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/vps2vpn-xray.service <<EOF
[Unit]
Description=vps2vpn Xray (VLESS + REALITY)
After=network-online.target
Wants=network-online.target

[Service]
User=vps2vpn
Group=vps2vpn
Environment=XRAY_LOCATION_ASSET=$LIB
ExecStart=$LIB/xray run -c $ETC/xray.json
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
NoNewPrivileges=yes
LimitNOFILE=1048576
Restart=always
RestartSec=2
TimeoutStopSec=15
UMask=0077
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
$NEW_HARDENING
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/vps2vpn-hysteria.service <<EOF
[Unit]
Description=vps2vpn Hysteria 2
After=network-online.target
Wants=network-online.target

[Service]
User=vps2vpn
Group=vps2vpn
Environment=HYSTERIA_DISABLE_UPDATE_CHECK=1
ExecStart=$LIB/hysteria server -c $ETC/hysteria.json --disable-update-check
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
LimitNOFILE=1048576
Restart=always
RestartSec=2
TimeoutStopSec=15
UMask=0077
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
$NEW_HARDENING
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

[Install]
WantedBy=multi-user.target
EOF
  cat > /etc/systemd/system/vps2vpn-tuic.service <<EOF
[Unit]
Description=vps2vpn sing-box (TUIC v5)
After=network-online.target
Wants=network-online.target

[Service]
User=vps2vpn
Group=vps2vpn
ExecStart=$LIB/sing-box run -c $ETC/tuic.json -D /var/lib/vps2vpn-tuic
StateDirectory=vps2vpn-tuic
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
NoNewPrivileges=yes
LimitNOFILE=1048576
Restart=always
RestartSec=2
TimeoutStopSec=15
UMask=0077
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
$NEW_HARDENING
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}

show_result() {
  local json url ports setup_done cloud how
  json="$1"
  url=$(printf '%s' "$json" | "$PY" -c 'import json,sys; print(json.load(sys.stdin)["url"])')
  ports=$(printf '%s' "$json" | "$PY" -c 'import json,sys; print("  ".join("%s/%s" % (p, t) for t, p in json.load(sys.stdin)["ports"]))')
  setup_done=$(printf '%s' "$json" | "$PY" -c 'import json,sys; print(1 if json.load(sys.stdin).get("setup_done") else 0)')
  cloud=$(printf '%s' "$json" | "$PY" -c 'import json,sys; print(json.load(sys.stdin).get("cloud") or "")')
  how=$(printf '%s' "$json" | "$PY" -c 'import json,sys; print(json.load(sys.stdin).get("cloud_firewall") or "")')
  echo
  if [ "${V2V_AUTO:-}" = 1 ]; then
    # One-click deployer: hand it the result in one machine-readable line (it holds the new admin
    # password, so the deployer hides this line and keeps it only on the owner's computer).
    printf 'V2V_RESULT:%s
' "$(printf '%s' "$json" | base64 | tr -d '
')"
    echo "${c_ok}${c_b}vps2vpn is ready. / 已装好，账号已自动建好。${c_0}"
    return
  fi
  if [ "$setup_done" = 1 ]; then
    echo "${c_ok}${c_b}vps2vpn is up to date. Users and settings are kept.${c_0}"
    echo "  已更新到最新版，用户和设置都保留。面板地址："
    echo
    echo "  ${c_b}$url${c_0}"
    echo
    return
  fi
  echo "${c_ok}${c_b}vps2vpn is installed.${c_0}"
  echo
  echo "  Open this link in your browser to finish (one click):"
  echo "  打开下面的链接，在网页里点一下就建好了："
  echo
  echo "  ${c_b}$url${c_0}"
  echo
  if [ -n "$cloud" ]; then
    echo "  ${c_b}This server is on $cloud. Its firewall is in the $cloud web console and usually blocks these ports.${c_0}"
    echo "  ${c_b}这台服务器在 $cloud 上。它的防火墙在网页控制台里，默认会挡住下面的端口，请先放行：${c_0}"
    echo "  $how"
    echo "  ${c_dim}Ports / 端口: $ports${c_0}"
  else
    echo "  ${c_dim}If the page does not load, open these ports in your cloud provider's firewall / security group:${c_0}"
    echo "  ${c_dim}打不开的话，去云服务商控制台的防火墙/安全组放行这些端口：${c_0}"
    echo "  $ports"
  fi
  printf '%s' "$json" | "$PY" -c 'import json,sys
for w in json.load(sys.stdin).get("warnings", []): print("  ! " + w)'
  echo
}

make_swapfile() {  # fallocate|dd -> 0 if /swapfile is active swap
  rm -f /swapfile
  (umask 077 && : > /swapfile) || return 1
  chattr +C /swapfile 2>/dev/null || true          # Btrfs: swap files must be NOCOW (no-op elsewhere)
  if [ "$1" = fallocate ]; then
    fallocate -l 1G /swapfile 2>/dev/null || return 1
  else
    dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none 2>/dev/null || return 1
  fi
  chmod 600 /swapfile || return 1
  selinux_label swapfile_t /swapfile
  mkswap /swapfile >/dev/null 2>&1 && swapon /swapfile 2>/dev/null
}

prepare_system() {
  # Small VPSes (512 MB) run out of memory during upgrades without swap.
  local mem_mb swap_kb free_mb
  mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
  swap_kb=$(awk '/SwapTotal/ {print $2}' /proc/meminfo)
  free_mb=$(df -Pm / | awk 'NR==2 {print $4}')
  if [ "$mem_mb" -lt 1000 ] && [ "$swap_kb" -eq 0 ] && [ "$free_mb" -gt 3000 ] && [ ! -e /swapfile ]; then
    say "only ${mem_mb} MB of memory: adding a 1 GB swap file / 内存较小，正在加 1 GB 虚拟内存"
    # fallocate is fast, but swapon rejects preallocated (unwritten) extents on some XFS/Btrfs setups:
    # if that happens, write the file out with dd and try once more.
    if make_swapfile fallocate || make_swapfile dd; then
      grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
    else
      rm -f /swapfile
      say "could not enable swap (continuing without it) / 虚拟内存没开成，不影响继续安装"
    fi
  fi
  # Certificates and TLS need a correct clock.
  command -v timedatectl >/dev/null && timedatectl set-ntp true 2>/dev/null || true
}

do_install() {
  need_root; detect_arch; install_packages; prepare_system; install_cores; install_app; install_units
  local json setup_done
  local auto=""; [ "${V2V_AUTO:-}" = 1 ] && auto="--auto"
  if ! json=$(PYTHONPATH="$LIB/app" "$PY" -m vps2vpn init --acme $auto | tail -1) || [ -z "$json" ]; then
    if [ -d "$LIB/app/vps2vpn.old" ]; then          # an upgrade failed during init: put the previous version back
      rm -rf "$LIB/app/vps2vpn" && mv "$LIB/app/vps2vpn.old" "$LIB/app/vps2vpn"
      systemctl restart vps2vpn 2>/dev/null || true
      die "the new version failed to initialize, so the previous version was restored${SNAPSHOT:+ (database too: sudo bash $SNAPSHOT/restore.sh)}"
    fi
    die "vps2vpn init failed"
  fi
  systemctl enable vps2vpn >/dev/null 2>&1
  systemctl restart vps2vpn
  setup_done=$(printf '%s' "$json" | "$PY" -c 'import json,sys; print(1 if json.load(sys.stdin).get("setup_done") else 0)' 2>/dev/null || echo 0)
  if [ "$setup_done" = 1 ]; then          # configured (upgrade or --auto): write configs for the new version
    PYTHONPATH="$LIB/app" "$PY" -m vps2vpn apply --force >/dev/null 2>&1 || true
  fi
  sleep 1
  if ! systemctl is-active --quiet vps2vpn; then
    journalctl -u vps2vpn -n 30 --no-pager
    if [ -d "$LIB/app/vps2vpn.old" ]; then          # an upgrade broke the panel: put the previous version back
      rm -rf "$LIB/app/vps2vpn" && mv "$LIB/app/vps2vpn.old" "$LIB/app/vps2vpn"
      systemctl restart vps2vpn
      die "the new version failed to start, so the previous version was restored${SNAPSHOT:+ (database too: sudo bash $SNAPSHOT/restore.sh)}"
    fi
    die "panel failed to start (the log above says why)
  面板没能启动，原因在上面的日志里。可以再运行一次安装命令试试；想看完整日志就运行  journalctl -u vps2vpn -n 50  看完整日志。"
  fi
  show_result "$json"
  if [ -n "$SNAPSHOT" ]; then
    echo "  ${c_dim}Roll back this upgrade (database + code) / 回滚这次升级:${c_0}  sudo bash $SNAPSHOT/restore.sh"
  fi
}

clear_speed_limits() {   # speed limits live in the kernel, not in files: take ours down, leave anyone else's alone
  if [ -d "$LIB/app" ]; then
    pick_python 2>/dev/null || true
    # from /: "python -c" imports from the current folder first, which could hold another vps2vpn checkout
    (cd / && PYTHONPATH="$LIB/app" timeout 60 "$PY" -c 'from vps2vpn import shaper; shaper.clear(log=lambda *a: None)') \
      >/dev/null 2>&1 || true
  fi
  # fallback (no Python, or the default route moved since the limits were set): our HTB root 1a5: on any card,
  # an ingress qdisc that redirects to our ifb device, the ifb device and our nft table. Most of them are not
  # there (no limits were set, a container without tc): every step may fail, and under set -e that must not end
  # the uninstall half way.
  if command -v tc >/dev/null 2>&1 && command -v ip >/dev/null 2>&1; then
    local dev
    for dev in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 || true); do
      [ "$dev" = v2vifb0 ] && continue
      if (tc qdisc show dev "$dev" 2>/dev/null || true) | grep -q 'htb 1a5:'; then
        tc qdisc del dev "$dev" root 2>/dev/null || true
      fi
      if (tc filter show dev "$dev" parent ffff: 2>/dev/null || true) | grep -q v2vifb0; then
        tc qdisc del dev "$dev" ingress 2>/dev/null || true
      fi
    done
    ip link del v2vifb0 2>/dev/null || true
  fi
  if command -v nft >/dev/null 2>&1; then
    nft delete table inet vps2vpn_shape 2>/dev/null || true
  fi
  return 0
}

do_uninstall() {
  need_root
  say "removing vps2vpn / 正在卸载 vps2vpn"
  systemctl disable --now vps2vpn vps2vpn-xray vps2vpn-hysteria vps2vpn-tuic vps2vpn-nft 2>/dev/null || true
  clear_speed_limits     # after the panel stopped (it would put them back), before its code is deleted
  rm -f /etc/systemd/system/vps2vpn*.service /usr/local/bin/vps2vpn /etc/sysctl.d/99-vps2vpn.conf \
    /etc/modules-load.d/vps2vpn.conf "$ETC/nft-hop.nft"
  command -v nft >/dev/null && nft delete table inet vps2vpn 2>/dev/null || true
  systemctl daemon-reload
  rm -rf "$LIB"
  if [ "${1:-}" = "--purge" ]; then rm -rf "$ETC" "$VAR" /var/lib/vps2vpn-tuic; userdel vps2vpn 2>/dev/null || true
  else echo "kept settings and users in $ETC and $VAR (use 'uninstall --purge' to delete them)"; fi
  echo "done. Kernel tuning returns to defaults after a reboot."
}

one_at_a_time() {   # a retried or double-clicked deploy must not run two installs over each other
  [ "$(id -u)" = 0 ] || return 0
  command -v flock >/dev/null 2>&1 || return 0
  # braces: a bare "exec 9>f 2>/dev/null" would send the rest of the installer's errors to /dev/null too
  { exec 9>"$LOCK"; } 2>/dev/null || return 0
  if ! flock -n 9; then
    say "another vps2vpn install is running; waiting for it (up to 10 minutes) / 另一个安装正在进行，最多等 10 分钟"
    flock -w 600 9 || die "another vps2vpn install is still running"
  fi
}

# sourced (tests): define the functions only
[ "${BASH_SOURCE[0]:-$0}" = "$0" ] || return 0

case "${1:-install}" in
  install|update|upgrade|uninstall) one_at_a_time ;;
esac
case "${1:-install}" in
  install|update|upgrade) do_install ;;
  info) pick_python || true; PYTHONPATH="$LIB/app" "$PY" -m vps2vpn info ;;
  uninstall) do_uninstall "${2:-}" ;;
  *) echo "usage: bash install.sh [install|info|uninstall [--purge]]"; exit 1 ;;
esac
