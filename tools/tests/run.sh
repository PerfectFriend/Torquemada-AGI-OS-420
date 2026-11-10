#!/usr/bin/env bash
# Verifies the bridge against the REAL sing-box binary: config validity for every protocol/mode, then real traffic
# through each protocol on loopback, WireGuard, OpenVPN (and interop with a real OpenVPN server if `openvpn` is installed).
# Needs: node, openssl, python3, curl; the sidecar fetched with `node tools/fetch-sidecars.mjs`.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; SB="${SINGBOX:-$HERE/../../app/src-tauri/binaries/sing-box-x86_64-unknown-linux-gnu}"
[ -x "$SB" ] || { echo "sing-box не найден: $SB (запусти node tools/fetch-sidecars.mjs или задай SINGBOX=...)"; exit 1; }
export SINGBOX="$SB"; rm -rf /tmp/bt; mkdir -p /tmp/bt/www; cd /tmp/bt
echo -n "W420-OK-$RANDOM" > www/index.html
"$SB" generate reality-keypair > rk.txt; "$SB" generate wg-keypair > wk1.txt; "$SB" generate wg-keypair > wk2.txt
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -subj "/CN=TestCA" -days 30 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout cl.key -out cl.csr -subj "/CN=client" 2>/dev/null; openssl x509 -req -in cl.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out cl.crt -days 30 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout srv.key -out srv.crt -subj "/CN=localhost" -days 30 -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout ov_s.key -out ov_s.csr -subj "/CN=server" 2>/dev/null; printf "extendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n" > ext_s.txt; openssl x509 -req -in ov_s.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out ov_s.crt -days 30 -extfile ext_s.txt 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout ov_c.key -out ov_c.csr -subj "/CN=client1" 2>/dev/null; printf "extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature\n" > ext_c.txt; openssl x509 -req -in ov_c.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out ov_c.crt -days 30 -extfile ext_c.txt 2>/dev/null
bad=0
for t in check_test e2e wg ovpn_e2e; do echo "=== $t ==="; node "$HERE/$t.js" || bad=1; done
if command -v openvpn >/dev/null; then echo "=== ovpn_real (interop with real OpenVPN server; needs /dev/net/tun) ==="; node "$HERE/ovpn_real.js" || true; fi

[ "${bad:-0}" = 0 ] && echo "ALL BRIDGE TESTS PASSED" || { echo "SOME BRIDGE TESTS FAILED"; exit 1; }
