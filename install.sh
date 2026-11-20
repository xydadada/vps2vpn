#!/usr/bin/env bash
# vps2vpn installer - turns a fresh Linux VPS into a private VPN server with a web panel.
#
#   bash install.sh            install, or upgrade an existing install (keeps users and settings)
#   bash install.sh info       show the panel link again
#   bash install.sh uninstall  remove everything vps2vpn added
#
# Supported: Debian 11+, Ubuntu 20.04+, RHEL/Rocky/Alma/CentOS Stream 8+, Fedora, openSUSE, Arch; x86_64 and arm64.
set -euo pipefail

XRAY_VERSION="v26.3.27"   # v26.10.21+ rejects REALITY logins from mihomo 1.19 / sing-box 1.14 (tested 2026-11-18)
HYSTERIA_VERSION="app/v2.14.0"
SINGBOX_VERSION="v1.14.4"   # TUIC v5 server; release hashes pinned below (sing-box publishes no checksum file)
SINGBOX_SHA256_amd64="699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968"
SINGBOX_SHA256_arm64="436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26"
REPO="${V2V_REPO:-xydadada/vps2vpn}"          # where the panel code is downloaded from when not run from a checkout
BRANCH="${V2V_BRANCH:-main}"
LIB=/usr/local/lib/vps2vpn
ETC=/etc/vps2vpn
VAR=/var/lib/vps2vpn

c_ok=$'\e[32m'; c_bad=$'\e[31m'; c_dim=$'\e[2m'; c_b=$'\e[1m'; c_0=$'\e[0m'
say()  { echo "${c_b}==>${c_0} $*"; }
die()  { echo "${c_bad}error:${c_0} $*" >&2; exit 1; }

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
  local pkgs="python3 openssl curl unzip nftables ca-certificates"
  say "installing system packages"
  if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq || true
    apt-get install -y -qq $pkgs >/dev/null
  elif command -v dnf >/dev/null; then dnf install -y -q $pkgs >/dev/null
  elif command -v yum >/dev/null; then yum install -y -q $pkgs >/dev/null
  elif command -v zypper >/dev/null; then zypper -nq install $pkgs >/dev/null
  elif command -v pacman >/dev/null; then pacman -Sy --noconfirm --needed python openssl curl unzip nftables ca-certificates >/dev/null
  else die "unknown package manager; install: $pkgs"; fi
  python3 -c 'import sys; assert sys.version_info >= (3, 8)' || die "python 3.8 or newer is required"
}

fetch() {  # url dest
  curl -fL --retry 3 --connect-timeout 15 -sS -o "$2" "$1" || die "download failed: $1"
}

install_cores() {
  local tmp; tmp=$(mktemp -d)
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
    case "$SB_ARCH" in
      amd64) want=$SINGBOX_SHA256_amd64 ;;
      arm64) want=$SINGBOX_SHA256_arm64 ;;
      *) die "unsupported sing-box architecture: $SB_ARCH" ;;
    esac
    got=$(sha256sum "$tmp/sb.tgz" | awk '{print $1}')
    [ "$want" = "$got" ] || die "sing-box checksum mismatch (expected $want, got $got)"
    mkdir -p "$tmp/sb" && tar -xzf "$tmp/sb.tgz" -C "$tmp/sb" --strip-components=1
    install -m 0755 "$tmp/sb/sing-box" "$LIB/sing-box.new" && mv -f "$LIB/sing-box.new" "$LIB/sing-box"
    echo "$SINGBOX_VERSION" > "$LIB/.sing-box-version"
  fi
  rm -rf "$tmp"
}

install_app() {
  local here; here=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo /nonexistent)
  local tmp; tmp=$(mktemp -d)
  if [ -n "${V2V_SRC:-}" ] && [ -f "$V2V_SRC" ]; then
    say "using panel code from $V2V_SRC"
    tar -xzf "$V2V_SRC" -C "$tmp"
  elif [ -f "$here/vps2vpn/__init__.py" ]; then
    say "using panel code next to this script"
    cp -r "$here/vps2vpn" "$tmp/"
  else
    say "downloading panel code from github.com/$REPO"
    fetch "https://github.com/$REPO/archive/refs/heads/$BRANCH.tar.gz" "$tmp/src.tgz"
    tar -xzf "$tmp/src.tgz" -C "$tmp" --strip-components=1
  fi
  [ -f "$tmp/vps2vpn/__init__.py" ] || die "panel code not found in the download"
  python3 -m compileall -q "$tmp/vps2vpn" >/dev/null || die "panel code does not compile with $(python3 --version)"
  mkdir -p "$LIB/app"
  rm -rf "$LIB/app/vps2vpn.new"
  cp -r "$tmp/vps2vpn" "$LIB/app/vps2vpn.new"
  rm -rf "$LIB/app/vps2vpn.old"
  [ -d "$LIB/app/vps2vpn" ] && mv "$LIB/app/vps2vpn" "$LIB/app/vps2vpn.old"
  mv "$LIB/app/vps2vpn.new" "$LIB/app/vps2vpn"
  rm -rf "$tmp"
  cat > /usr/local/bin/vps2vpn <<EOF
#!/bin/sh
PYTHONPATH=$LIB/app exec python3 -m vps2vpn "\$@"
EOF
  chmod 0755 /usr/local/bin/vps2vpn
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
PrivateTmp=yes
ProtectHome=yes

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
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

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
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

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
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

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

prepare_system() {
  # Small VPSes (512 MB) run out of memory during upgrades without swap.
  local mem_mb swap_kb free_mb
  mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
  swap_kb=$(awk '/SwapTotal/ {print $2}' /proc/meminfo)
  free_mb=$(df -Pm / | awk 'NR==2 {print $4}')
  if [ "$mem_mb" -lt 1000 ] && [ "$swap_kb" -eq 0 ] && [ "$free_mb" -gt 3000 ] && [ ! -e /swapfile ]; then
    say "only ${mem_mb} MB of memory: adding a 1 GB swap file"
    if fallocate -l 1G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none; then
      if chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile; then
        grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
      else
        rm -f /swapfile
      fi
    fi
  fi
  # Certificates and TLS need a correct clock.
  command -v timedatectl >/dev/null && timedatectl set-ntp true 2>/dev/null || true
}

do_install() {
  need_root; detect_arch; install_packages; prepare_system; install_cores; install_app; install_units
  local first=1; [ -f "$VAR/vps2vpn.db" ] && first=0
  local json
  local auto=""; [ "${V2V_AUTO:-}" = 1 ] && auto="--auto"
  if ! json=$(PYTHONPATH="$LIB/app" python3 -m vps2vpn init --acme $auto | tail -1); then
    restore_previous_app
    die "initialization failed; restored the previous panel code when available"
  fi
  if ! systemctl enable vps2vpn >/dev/null 2>&1 || ! systemctl restart vps2vpn; then
    restore_previous_app
    die "panel service failed; restored the previous panel code when available"
  fi
  if [ "$first" = 0 ] || [ -n "$auto" ]; then
    if ! PYTHONPATH="$LIB/app" python3 -m vps2vpn apply --force; then
      restore_previous_app
      die "core configuration failed; restored the previous panel code when available"
    fi
  fi
  sleep 1
  if ! systemctl is-active --quiet vps2vpn; then
    journalctl -u vps2vpn -n 30 --no-pager
    restore_previous_app
    die "panel failed to start; restored the previous panel code when available"
  fi
  show_result "$json"
}

restore_previous_app() {
  if [ -d "$LIB/app/vps2vpn.old" ]; then
    rm -rf "$LIB/app/vps2vpn" && mv "$LIB/app/vps2vpn.old" "$LIB/app/vps2vpn"
    systemctl restart vps2vpn || true
    PYTHONPATH="$LIB/app" python3 -m vps2vpn apply --force || true
  fi
}

do_uninstall() {
  need_root
  say "removing vps2vpn"
  systemctl disable --now vps2vpn vps2vpn-xray vps2vpn-hysteria vps2vpn-tuic 2>/dev/null || true
  rm -f /etc/systemd/system/vps2vpn*.service /usr/local/bin/vps2vpn /etc/sysctl.d/99-vps2vpn.conf
  command -v nft >/dev/null && nft delete table inet vps2vpn 2>/dev/null || true
  systemctl daemon-reload
  rm -rf "$LIB"
  if [ "${1:-}" = "--purge" ]; then rm -rf "$ETC" "$VAR" /var/lib/vps2vpn-tuic; userdel vps2vpn 2>/dev/null || true
  else echo "kept settings and users in $ETC and $VAR (use 'uninstall --purge' to delete them)"; fi
  echo "done. Kernel tuning returns to defaults after a reboot."
}

case "${1:-install}" in
  install|update|upgrade) do_install ;;
  info) PYTHONPATH="$LIB/app" python3 -m vps2vpn info ;;
  uninstall) do_uninstall "${2:-}" ;;
  *) echo "usage: bash install.sh [install|info|uninstall [--purge]]"; exit 1 ;;
esac
