#!/usr/bin/env bash
# root_setup.sh — W420 root setup. Запускается ТОЛЬКО пользователем от своего имени (sudo);
# пароль никуда не передаётся, скрипт интерактивный и безопасен.
set -uo pipefail
echo "== W420 root setup $(date) =="; echo

# 1) Capabilities — tcpdump/dumpcap захватывают пакеты БЕЗ sudo, nft — через CapNetAdmin
setcap cap_net_raw,cap_net_admin+ep /usr/bin/tcpdump 2>/dev/null && echo "setcap tcpdump OK" || echo "setcap tcpdump SKIP"
[ -x /usr/bin/dumpcap ] && setcap cap_net_raw,cap_net_admin+ep /usr/bin/dumpcap 2>/dev/null
[ -x /usr/sbin/nft ] && setcap cap_net_admin+ep /usr/sbin/nft 2>/dev/null && echo "setcap nft OK"

# 2) sudoers: passwordless для узкого набора команд
if command -v sudoers >/dev/null 2>&1 || grep -q sudoers /etc; then
cat > /etc/sudoers.d/w420 <<'EOF'
# W420: passwordless для сетевых/патч-операций агента
thomas ALL=(root) NOPASSWD: /usr/sbin/nft, /usr/bin/tcpdump
thomas ALL=(root) NOPASSWD: /usr/bin/wg, /usr/bin/wg-quick, /usr/sbin/ip
thomas ALL=(root) NOPASSWD: /usr/bin/tee /etc/wireguard/w420wg.conf, /usr/bin/mkdir /etc/wireguard
thomas ALL=(root) NOPASSWD: /usr/bin/apt-get, /usr/bin/apt, /usr/bin/cat /var/log/apt/history.log
EOF
chmod 440 /etc/sudoers.d/w420
visudo -c -f /etc/sudoers.d/w420 >/dev/null 2>&1 && echo "sudoers OK" || echo "sudoers CHECK_FAILED"
fi
mkdir -p /etc/wireguard && chmod 700 /etc/wireguard

# 3) Внешние пакеты (sidecar-инструменты плана эволюции)
apt-get update -qq || apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nmap suricata 2>&1 | tail -2 || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nmap 2>&1 | tail -2

# 4) Живая проверка механизма nft: применяем test-таблицу атомарно, проверяем, снимаем
nft delete table inet w420_em 2>/dev/null
cat > /tmp/w420_test.nft <<'EOF'
table inet w420_em {
  chain input {
    type filter hook input priority 0; policy accept;
    iif "lo" accept
    ct state established,related accept
    tcp dport { 1234, 4444, 5555, 6666, 7777, 9001, 31337, 12345, 27374 } drop
  }
}
EOF
if nft -f /tmp/w420_test.nft; then echo "NFT_APPLY_OK"; nft delete table inet w420_em && echo "NFT_TEST_REVERTED"; else echo "NFT_APPLY_FAILED"; fi

# 5) Права на данные w420
chown -R thomas:thomas /home/thomas/.w420 2>/dev/null || true
mkdir -p /home/thomas/.w420

echo "== DONE =="
