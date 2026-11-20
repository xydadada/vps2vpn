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
PINNED_TAG="v0.2.5"   # release used when GitHub's API cannot be reached; bump it with every release
REF="${V2V_REF:-${V2V_BRANCH:-}}"   # development only: install this branch/tag/commit instead, UNVERIFIED
LIB=/usr/local/lib/vps2vpn
ETC=/etc/vps2vpn
VAR=/var/lib/vps2vpn
SNAPS="$VAR/upgrade-snapshots"     # database + code saved before each upgrade (root only, last 3 kept)
SNAPSHOT=""                         # the one made by this run

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
  [ "$(id -u)" = 0 ] || die "please run as root, e.g.:  sudo bash install.sh"
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

install_packages() {
  local pkgs=(python3 openssl tar unzip nftables ca-certificates)
  command -v curl >/dev/null 2>&1 || pkgs+=(curl)     # RHEL ships curl-minimal, which conflicts with "curl"
  say "installing system packages"
  if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq || true
    apt-get install -y -qq "${pkgs[@]}" >/dev/null
  elif command -v dnf >/dev/null; then dnf install -y -q "${pkgs[@]}" >/dev/null
  elif command -v yum >/dev/null; then yum install -y -q "${pkgs[@]}" >/dev/null
  elif command -v zypper >/dev/null; then zypper -nq install "${pkgs[@]}" >/dev/null
  elif command -v pacman >/dev/null; then
    local pac=(python openssl tar unzip nftables ca-certificates)
    command -v curl >/dev/null 2>&1 || pac+=(curl)
    pacman -Sy --noconfirm --needed "${pac[@]}" >/dev/null
  else die "unknown package manager; install: ${pkgs[*]}"; fi
  python3 -c 'import sys; assert sys.version_info >= (3, 8)' || die "python 3.8 or newer is required"
}

fetch() {  # url dest
  curl -fL --retry 3 --connect-timeout 15 -sS -o "$2" "$1" || die "download failed: $1"
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
  python3 -c 'import re, sys
v = lambda s: tuple(int(x) for x in re.findall(r"[0-9]+", s))
sys.exit(0 if v(sys.argv[1]) < v(sys.argv[2]) else 1)' "$1" "$2"
}

latest_release_tag() {  # -> tag of the newest published release, or nothing if GitHub's API cannot be reached
  curl -fsS --connect-timeout 10 --max-time 20 -H 'Accept: application/vnd.github+json' \
    "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null | python3 -c 'import json, re, sys
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
      say "GitHub's API is unreachable; using the pinned release $tag"
    fi
    name="vps2vpn-$tag.tar.gz"
    say "downloading vps2vpn $tag from github.com/$REPO/releases"
    if try_fetch "https://github.com/$REPO/releases/download/$tag/$name" "$tmp/src.tgz"; then
      # a release that has the tarball must have its checksum too, and it must match
      fetch "https://github.com/$REPO/releases/download/$tag/$name.sha256" "$tmp/src.tgz.sha256"
      want=$(awk -v f="$name" '{n=$2; sub(/^\*/, "", n); if (NF == 1 || n == f) {print $1; exit}}' "$tmp/src.tgz.sha256")
      got=$(sha256sum "$tmp/src.tgz" | awk '{print $1}')
      [ -n "$want" ] && [ "$want" = "$got" ] \
        || die "vps2vpn $tag checksum mismatch (expected ${want:-nothing}, got $got): refusing to install it"
      say "checksum OK: $got"
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
  say "saving the current database and code to $dir"
  (umask 077 && mkdir -p "$dir") || die "could not create $dir (disk full?); nothing was changed"
  chmod 0700 "$SNAPS" "$dir"
  if [ -f "$db" ]; then
    # SQLite's online backup: consistent even while the panel is writing (a plain copy of a WAL database is not)
    if ! (umask 077 && python3 -c 'import sqlite3, sys
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
PYTHONPATH="$LIB/app" python3 -m vps2vpn apply --force >/dev/null 2>&1 || true
systemctl start vps2vpn
echo "vps2vpn is back to the snapshot of $stamp UTC (version ${old:-unknown})."
EOF
  # keep the newest 3 (names start with the UTC time, so the glob is in age order)
  local all=() d i
  for d in "$SNAPS"/[0-9]*-v*/; do if [ -d "$d" ]; then all+=("${d%/}"); fi; done
  for ((i = 0; i + 3 < ${#all[@]}; i++)); do rm -rf -- "${all[$i]}"; done
  SNAPSHOT="$dir"
  say "to roll back this upgrade later:  sudo bash $SNAPSHOT/restore.sh"
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
    say "downloading Xray $XRAY_VERSION"
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
    say "downloading Hysteria $HYSTERIA_VERSION"
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
    say "downloading sing-box $SINGBOX_VERSION (TUIC)"
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
  local here; here=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo /nonexistent)
  local tmp; tmp=$(mktemp -d)
  _TMPDIRS+=("$tmp")
  if [ -n "${V2V_SRC:-}" ] && [ -f "$V2V_SRC" ]; then
    say "using panel code from $V2V_SRC"
    tar --no-same-owner --no-same-permissions -xzf "$V2V_SRC" -C "$tmp"
  elif [ -f "$here/vps2vpn/__init__.py" ]; then
    say "using panel code next to this script"
    cp -r "$here/vps2vpn" "$tmp/"
  else
    fetch_panel_code "$tmp"
  fi
  [ -f "$tmp/vps2vpn/__init__.py" ] || die "panel code not found in the download"
  python3 -m compileall -q "$tmp/vps2vpn" >/dev/null || die "panel code does not compile with $(python3 --version)"
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
PYTHONPATH=$LIB/app exec python3 -m vps2vpn "\$@"
EOF
  chmod 0755 /usr/local/bin/vps2vpn
  selinux_label bin_t /usr/local/bin/vps2vpn
}

install_units() {
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
ExecStart=/usr/bin/env python3 -m vps2vpn serve
Restart=always
RestartSec=3
TimeoutStopSec=15
LimitNOFILE=65536
PrivateTmp=yes
ProtectHome=yes
ProtectClock=yes
ProtectKernelLogs=yes
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
ProtectClock=yes
ProtectKernelLogs=yes
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
ProtectClock=yes
ProtectKernelLogs=yes
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
ProtectClock=yes
ProtectKernelLogs=yes
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
  url=$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["url"])')
  ports=$(printf '%s' "$json" | python3 -c 'import json,sys; print("  ".join("%s/%s" % (p, t) for t, p in json.load(sys.stdin)["ports"]))')
  setup_done=$(printf '%s' "$json" | python3 -c 'import json,sys; print(1 if json.load(sys.stdin).get("setup_done") else 0)')
  cloud=$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("cloud") or "")')
  how=$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("cloud_firewall") or "")')
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
  printf '%s' "$json" | python3 -c 'import json,sys
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
    say "only ${mem_mb} MB of memory: adding a 1 GB swap file"
    # fallocate is fast, but swapon rejects preallocated (unwritten) extents on some XFS/Btrfs setups:
    # if that happens, write the file out with dd and try once more.
    if make_swapfile fallocate || make_swapfile dd; then
      grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
    else
      rm -f /swapfile
      say "could not enable swap (continuing without it)"
    fi
  fi
  # Certificates and TLS need a correct clock.
  command -v timedatectl >/dev/null && timedatectl set-ntp true 2>/dev/null || true
}

do_install() {
  need_root; detect_arch; install_packages; prepare_system; install_cores; install_app; install_units
  local json setup_done
  local auto=""; [ "${V2V_AUTO:-}" = 1 ] && auto="--auto"
  if ! json=$(PYTHONPATH="$LIB/app" python3 -m vps2vpn init --acme $auto | tail -1) || [ -z "$json" ]; then
    if [ -d "$LIB/app/vps2vpn.old" ]; then          # an upgrade failed during init: put the previous version back
      rm -rf "$LIB/app/vps2vpn" && mv "$LIB/app/vps2vpn.old" "$LIB/app/vps2vpn"
      systemctl restart vps2vpn 2>/dev/null || true
      die "the new version failed to initialize, so the previous version was restored${SNAPSHOT:+ (database too: sudo bash $SNAPSHOT/restore.sh)}"
    fi
    die "vps2vpn init failed"
  fi
  systemctl enable vps2vpn >/dev/null 2>&1
  systemctl restart vps2vpn
  setup_done=$(printf '%s' "$json" | python3 -c 'import json,sys; print(1 if json.load(sys.stdin).get("setup_done") else 0)' 2>/dev/null || echo 0)
  if [ "$setup_done" = 1 ]; then          # configured (upgrade or --auto): write configs for the new version
    PYTHONPATH="$LIB/app" python3 -m vps2vpn apply --force >/dev/null 2>&1 || true
  fi
  sleep 1
  if ! systemctl is-active --quiet vps2vpn; then
    journalctl -u vps2vpn -n 30 --no-pager
    if [ -d "$LIB/app/vps2vpn.old" ]; then          # an upgrade broke the panel: put the previous version back
      rm -rf "$LIB/app/vps2vpn" && mv "$LIB/app/vps2vpn.old" "$LIB/app/vps2vpn"
      systemctl restart vps2vpn
      die "the new version failed to start, so the previous version was restored${SNAPSHOT:+ (database too: sudo bash $SNAPSHOT/restore.sh)}"
    fi
    die "panel failed to start"
  fi
  show_result "$json"
  if [ -n "$SNAPSHOT" ]; then
    echo "  ${c_dim}Roll back this upgrade (database + code) / 回滚这次升级:${c_0}  sudo bash $SNAPSHOT/restore.sh"
  fi
}

do_uninstall() {
  need_root
  say "removing vps2vpn"
  systemctl disable --now vps2vpn vps2vpn-xray vps2vpn-hysteria vps2vpn-tuic vps2vpn-nft 2>/dev/null || true
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
  exec 9>/run/vps2vpn-install.lock 2>/dev/null || return 0
  if ! flock -n 9; then
    say "another vps2vpn install is running; waiting for it (up to 10 minutes)"
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
  info) PYTHONPATH="$LIB/app" python3 -m vps2vpn info ;;
  uninstall) do_uninstall "${2:-}" ;;
  *) echo "usage: bash install.sh [install|info|uninstall [--purge]]"; exit 1 ;;
esac
