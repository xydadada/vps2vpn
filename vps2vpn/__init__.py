"""vps2vpn - turn a fresh VPS into a private proxy server with a web panel.

Cores: Xray (VLESS + REALITY over TCP), Hysteria 2 and sing-box (TUIC v5), both QUIC over UDP.
The panel itself only needs the Python 3 standard library.
"""
VERSION = '0.2.14'

# Pinned core versions. install.sh downloads exactly these and checks their hashes.
XRAY_VERSION = 'v26.3.27'   # newer releases (v26.10.21+) reject REALITY from mihomo/sing-box clients
HYSTERIA_VERSION = 'app/v2.14.0'
SINGBOX_VERSION = 'v1.14.4'   # TUIC v5 server
