#!/bin/bash
# Acceptance test on a real, disposable VPS after `install.sh install`.
#   sudo bash tests/vps_acceptance.sh            checks only
#   sudo bash tests/vps_acceptance.sh --full     also: reinstall (idempotent), uninstall keeps data, reinstall again
# Prints PASS/FAIL per check and exits non-zero on any failure. Prints no secrets.
set -u
FULL=0; [ "${1:-}" = "--full" ] && FULL=1
pass=0; fail=0
ok()  { echo "PASS $*"; pass=$((pass + 1)); }
bad() { echo "FAIL $*"; fail=$((fail + 1)); }
chk() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
HERE=$(cd "$(dirname "$0")/.." && pwd)

settings() {   # read one setting through the installed package (falls back to defaults correctly)
  PYTHONPATH=/usr/local/lib/vps2vpn/app python3 -c 'import sys; from vps2vpn import db; print(db.settings()[sys.argv[1]])' "$1"
}

checks() {
  echo "== services"
  for u in vps2vpn vps2vpn-xray vps2vpn-hysteria vps2vpn-tuic; do chk "$u active" systemctl is-active --quiet "$u"; done
  chk "xray runs as unprivileged user" bash -c "ps -o user= -C xray | grep -qx vps2vpn"
  chk "hysteria runs as unprivileged user" bash -c "ps -o user= -C hysteria | grep -qx vps2vpn"
  chk "sing-box (TUIC) runs as unprivileged user" bash -c "ps -o user= -C sing-box | grep -qx vps2vpn"
  echo "== ports"
  local pp rp hp tp
  pp=$(settings panel_port); rp=$(settings reality_port); hp=$(settings hy2_port); tp=$(settings tuic_port)
  chk "panel listening on TCP $pp" bash -c "ss -Hltn 'sport = :$pp' | grep -q ."
  chk "REALITY listening on TCP $rp" bash -c "ss -Hltn 'sport = :$rp' | grep -q ."
  chk "Hysteria listening on UDP $hp" bash -c "ss -Hlun 'sport = :$hp' | grep -q ."
  chk "TUIC listening on UDP $tp" bash -c "ss -Hlun 'sport = :$tp' | grep -q ."
  if [ "$(settings hy2_hop)" = "True" ]; then chk "port hopping nft table" bash -c "nft list table inet vps2vpn | grep -q redirect"; fi
  echo "== panel"
  local path code
  path=$(settings panel_path)
  code=$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:$pp/$path/")
  [ "$code" = 200 ] && ok "panel answers over TLS" || bad "panel answers over TLS (HTTP $code)"
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$pp/$path/")
  [ "$code" = 301 ] && ok "plain HTTP panel redirects to HTTPS" || bad "plain HTTP panel redirects (HTTP $code)"
  code=$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:$pp/")
  [ "$code" = 404 ] && ok "panel hidden without secret path" || bad "panel hidden without secret path (HTTP $code)"
  echo "== kernel and system"
  chk "BBR on" bash -c "sysctl -n net.ipv4.tcp_congestion_control | grep -qx bbr"
  chk "rmem_max >= 7 MB" bash -c "[ \$(sysctl -n net.core.rmem_max) -ge 7340032 ]"
  chk "time synchronized" bash -c "timedatectl show -p NTPSynchronized --value | grep -qx yes"
  local exposed
  exposed=$(find /etc/vps2vpn /var/lib/vps2vpn -type f -perm -o=r \
    ! -name '*.crt' ! -name '*.crt.host' ! -path '/var/lib/vps2vpn/rules/*' \
    -printf '%m %p\\n')
  if [ -z "$exposed" ]; then
    ok "secrets not world-readable (public certificates and rule files aside)"
  else
    bad "secrets not world-readable (public certificates and rule files aside)"
    # Only names and modes, NEVER contents or authentication tokens.
    printf 'Exposed file modes and paths:\\n%s\\n' "$exposed"
  fi
  echo "== self-check (vps2vpn doctor)"
  if vps2vpn doctor; then ok "doctor reports no problems"; else bad "doctor found problems (see above)"; fi
  echo "== certificate"
  if openssl s_client -connect "127.0.0.1:$pp" -servername "$(settings public_host)" </dev/null 2>/dev/null \
      | openssl x509 -noout -issuer 2>/dev/null | grep -qi "let's encrypt"; then ok "Let's Encrypt certificate in use"
  else echo "INFO self-signed certificate in use (TCP 80 closed, or not issued yet)"; fi
  echo "== server speed (vps2vpn bench --quick)"
  vps2vpn bench --quick || true
}

checks
if [ $FULL = 1 ]; then
  echo "== reinstall over a running install"
  before=$(settings reality_private_key | sha256sum)
  log1=$(mktemp /tmp/v2v-reinstall-XXXXXX.log)
  if V2V_SRC="${V2V_SRC:-}" bash "$HERE/install.sh" install >"$log1" 2>&1; then ok "reinstall"; rm -f "$log1"; else bad "reinstall (see $log1)"; fi
  [ "$(settings reality_private_key | sha256sum)" = "$before" ] && ok "keys survive reinstall" || bad "keys changed on reinstall"
  echo "== uninstall keeps data, reinstall restores service"
  bash "$HERE/install.sh" uninstall >/dev/null 2>&1
  chk "units removed" bash -c "! systemctl cat vps2vpn >/dev/null 2>&1"
  chk "data kept" test -f /var/lib/vps2vpn/vps2vpn.db
  log2=$(mktemp /tmp/v2v-reinstall2-XXXXXX.log)
  if V2V_SRC="${V2V_SRC:-}" bash "$HERE/install.sh" install >"$log2" 2>&1; then ok "reinstall after uninstall"; rm -f "$log2"; else bad "reinstall after uninstall (see $log2)"; fi
  [ "$(settings reality_private_key | sha256sum)" = "$before" ] && ok "same keys after uninstall + install" || bad "keys changed after uninstall + install"
  checks
fi
echo
echo "$pass passed, $fail failed"
[ $fail = 0 ]
