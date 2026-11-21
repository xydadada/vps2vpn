#!/bin/bash
# Run the real install.sh from this checkout inside a throwaway container that boots systemd as PID 1,
# the way a freshly rented VPS would run it, then check the result and the upgrade path.
#
#   bash tests/container_install.sh debian:12        (needs Docker; used by CI for every supported distro)
#
# The container starts with nothing but its distro's base image plus systemd: everything else
# (python3, openssl, curl, nftables...) must be installed by install.sh itself. Prints no secrets:
# the panel link, its secret path and the server's public address are masked.
set -euo pipefail
IMAGE="${1:?usage: bash tests/container_install.sh <image, e.g. debian:12>}"
HERE=$(cd "$(dirname "$0")/.." && pwd)
NAME="v2v-$(printf '%s' "$IMAGE" | tr -c 'a-zA-Z0-9' '-')"
TAG="v2v-test:$(printf '%s' "$IMAGE" | tr -c 'a-zA-Z0-9.' '-')"
APP=/usr/local/lib/vps2vpn/app
pass=0; fail=0
ok()  { echo "PASS $*"; pass=$((pass + 1)); }
bad() { echo "FAIL $*"; fail=$((fail + 1)); }
step() { echo; echo "::group::$*"; }
endstep() { echo "::endgroup::"; }
mask() { sed -E -e 's#(https?://)[^ ]*#\1***#g' -e 's/[0-9]{1,3}(\.[0-9]{1,3}){3}/x.x.x.x/g'; }
in_c() { docker exec "$NAME" "$@"; }
py() {  # code [args] -> run with the Python the installer chose for the panel (python3 may be too old)
  docker exec -e PYTHONPATH="$APP" "$NAME" sh -c \
    'p=$(sed -n "s/.* exec \([^ ]*\) -m vps2vpn.*/\1/p" /usr/local/bin/vps2vpn 2>/dev/null); exec "${p:-python3}" -c "$@"' sh "$@"
}
setting() { py 'import sys; from vps2vpn import db; print(db.settings()[sys.argv[1]])' "$1"; }

case "$IMAGE" in        # just enough to boot systemd; a real VPS image has at least this
  debian:*|ubuntu:*)
    PREP='apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus >/dev/null && rm -rf /var/lib/apt/lists/*'
    INIT=/lib/systemd/systemd ;;
  *rocky*|*alma*|*centos*|fedora:*)
    PREP='(command -v dnf >/dev/null && dnf install -y -q systemd || yum install -y -q systemd) >/dev/null && (dnf clean all || yum clean all) >/dev/null'
    INIT=/usr/lib/systemd/systemd ;;
  *) echo "unknown image family: $IMAGE" >&2; exit 2 ;;
esac

cleanup() {
  if [ "$fail" -gt 0 ] || [ "${KEEP:-}" = 1 ]; then
    echo "== journal (last 80 lines of vps2vpn units)"
    in_c journalctl -u vps2vpn -u vps2vpn-xray -u vps2vpn-hysteria -u vps2vpn-tuic -n 80 --no-pager 2>/dev/null | mask || true
  fi
  [ "${KEEP:-}" = 1 ] || docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

step "build $IMAGE with systemd"
printf 'FROM %s\nRUN %s\nSTOPSIGNAL SIGRTMIN+3\nCMD ["%s"]\n' "$IMAGE" "$PREP" "$INIT" \
  | docker build --progress=plain -t "$TAG" - > /tmp/v2v-build.txt 2>&1   || { tail -n 40 /tmp/v2v-build.txt; exit 1; }
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  "$TAG" >/dev/null
for _ in $(seq 60); do
  state=$(in_c systemctl is-system-running 2>/dev/null || true)
  case "$state" in running|degraded) break ;; esac
  sleep 1
done
echo "systemd: $state"
in_c sh -c '. /etc/os-release; echo "$PRETTY_NAME"'
endstep

# the panel code exactly as a release tarball would carry it; install.sh alone, like the one-line download
tar -czf /tmp/v2v-src.tgz -C "$HERE" --exclude=__pycache__ vps2vpn
docker cp /tmp/v2v-src.tgz "$NAME:/root/v.tgz"
docker cp "$HERE/install.sh" "$NAME:/root/install.sh"

panel_code() {  # [setup] -> HTTP status of the panel page over TLS, asked from the runner like a browser would
  local ip port path
  ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NAME")
  port=$(setting panel_port); path=$(setting panel_path)
  curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "https://$ip:$port/$path/" || true
}

wait_panel() {  # -> 0 once the panel answers 200
  for _ in $(seq 20); do [ "$(panel_code)" = 200 ] && return 0; sleep 1; done
  return 1
}

run_install() {  # what -> runs install.sh from the checkout's tarball, shows its output, and on failure where it stopped
  local rc=0
  in_c env V2V_SRC=/root/v.tgz PS4='+ ${LINENO}: ' bash -x /root/install.sh install > /tmp/v2v-trace.txt 2>&1 || rc=$?
  grep -v '^+' /tmp/v2v-trace.txt > /tmp/v2v-out.txt || true
  mask < /tmp/v2v-out.txt
  if [ "$rc" = 0 ]; then ok "$1 exits 0"; else
    bad "$1 exits 0 (exit $rc); the installer's last steps:"
    grep '^+' /tmp/v2v-trace.txt | tail -n 15 | cut -c1-200 | mask
  fi
}

step "fresh install"
run_install "install.sh install"
grep -q 'vps2vpn is installed' /tmp/v2v-out.txt && ok "installer prints the setup link" || bad "installer prints the setup link"
endstep

step "after the first install"
py 'import sys; print("panel runs on Python", sys.version.split()[0], sys.executable)' || true
for u in vps2vpn vps2vpn-xray vps2vpn-hysteria vps2vpn-tuic; do
  in_c test -f "/etc/systemd/system/$u.service" && ok "$u.service written" || bad "$u.service written"
done
unknown=$(in_c sh -c 'systemd-analyze verify /etc/systemd/system/vps2vpn*.service 2>&1' \
  | grep -i vps2vpn | grep -iE 'unknown|invalid|failed to parse|ignoring' || true)
[ -z "$unknown" ] && ok "unit files parse with this systemd ($(in_c systemctl --version | head -1))" \
  || { bad "unit files parse with this systemd"; echo "$unknown"; }
in_c systemctl is-enabled --quiet vps2vpn && ok "panel enabled at boot" || bad "panel enabled at boot"
in_c systemctl is-active --quiet vps2vpn && ok "panel running" || bad "panel running"
wait_panel && ok "panel answers HTTPS on its port" || bad "panel answers HTTPS on its port (HTTP $(panel_code))"
in_c test -x /usr/local/bin/vps2vpn && ok "vps2vpn command installed" || bad "vps2vpn command installed"
endstep

step "finish setup and start the proxy cores"
py 'from vps2vpn.__main__ import quick_setup; quick_setup()' >/dev/null && ok "quick setup" || bad "quick setup"
in_c vps2vpn apply --force >/dev/null 2>&1 && ok "vps2vpn apply" || bad "vps2vpn apply"
sleep 3
for u in vps2vpn-xray vps2vpn-hysteria vps2vpn-tuic; do
  in_c systemctl is-active --quiet "$u" && ok "$u running" || bad "$u running"
done
for u in vps2vpn-xray vps2vpn-hysteria vps2vpn-tuic; do
  [ "$(in_c sh -c "stat -c %U /proc/\$(systemctl show -p MainPID --value $u)" 2>/dev/null)" = vps2vpn ] \
    && ok "$u runs unprivileged" || bad "$u runs unprivileged"
done
wait_panel && ok "panel answers after setup" || bad "panel answers after setup"
# what an upgrade must keep: the admin login and the users (compared inside the container, never printed)
py 'import hashlib; from vps2vpn import db; s = db.settings()
print(hashlib.sha256((s["admin_hash"] + "|" + ",".join(sorted(u["sub_token"] for u in db.users()))).encode()).hexdigest())' \
  > /tmp/v2v-before.txt || true
endstep

step "second run: upgrade over the running install"
run_install "second install.sh run"
grep -q 'up to date' /tmp/v2v-out.txt && ok "reports an upgrade, not a new install" || bad "reports an upgrade, not a new install"
snap=$(in_c sh -c 'ls -d /var/lib/vps2vpn/upgrade-snapshots/*/ 2>/dev/null | tail -1' || true)
if [ -n "$snap" ] && in_c test -s "${snap}vps2vpn.db" && in_c test -s "${snap}app.tar.gz" && in_c test -f "${snap}restore.sh"; then
  ok "snapshot taken (database, code, restore.sh)"
else
  bad "snapshot taken (database, code, restore.sh)"
fi
py 'import hashlib; from vps2vpn import db; s = db.settings()
print(hashlib.sha256((s["admin_hash"] + "|" + ",".join(sorted(u["sub_token"] for u in db.users()))).encode()).hexdigest())' \
  > /tmp/v2v-after.txt || true
[ -s /tmp/v2v-after.txt ] && cmp -s /tmp/v2v-before.txt /tmp/v2v-after.txt && ok "admin login and users kept" || bad "admin login and users kept"
[ "$(setting setup_done)" = True ] && ok "setup stays done" || bad "setup stays done"
wait_panel && ok "panel answers after the upgrade" || bad "panel answers after the upgrade"
for u in vps2vpn-xray vps2vpn-hysteria vps2vpn-tuic; do
  in_c systemctl is-active --quiet "$u" && ok "$u running after the upgrade" || bad "$u running after the upgrade"
done
endstep

step "roll back with the snapshot"
if [ -n "$snap" ] && in_c bash "${snap}restore.sh" >/dev/null 2>&1; then ok "restore.sh"; else bad "restore.sh"; fi
wait_panel && ok "panel answers after the rollback" || bad "panel answers after the rollback"
endstep

step "verified release download (what the one-line install fetches)"
if in_c env V2V_ALLOW_DOWNGRADE=1 bash -c 'source /root/install.sh; t=$(mktemp -d); fetch_panel_code "$t" && test -f "$t/vps2vpn/__init__.py"' 2>&1 | mask; then
  ok "latest release downloads and verifies"
else
  bad "latest release downloads and verifies"
fi
endstep

step "uninstall keeps the data, reinstall picks it up"
in_c bash /root/install.sh uninstall >/dev/null 2>&1 && ok "uninstall" || bad "uninstall"
in_c sh -c '! systemctl is-active --quiet vps2vpn && [ ! -e /etc/systemd/system/vps2vpn.service ]' && ok "services removed" || bad "services removed"
in_c test -s /var/lib/vps2vpn/vps2vpn.db && ok "database kept" || bad "database kept"
run_install "reinstall"
grep -q 'up to date' /tmp/v2v-out.txt && ok "reinstall finds the old setup" || bad "reinstall finds the old setup"
wait_panel && ok "panel answers after reinstall" || bad "panel answers after reinstall"
endstep

echo
echo "$IMAGE: $pass passed, $fail failed"
[ "$fail" = 0 ]
