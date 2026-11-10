#!/usr/bin/env bash
# W420 root-setup: выполняет ВСЁ, что в приложении требовало root.
# Запуск владельцем:  sudo bash /home/thomas/w420-install/scripts/root_setup.sh
# Пароль вводится локально в своём терминале и никуда не передаётся.
set -uo pipefail
echo "== W420 root setup $(date) =="

# 1) Capabilities: tcpdump/dumpcap захватывают пакеты БЕЗ sudo, nft управляет таблицами без полного root
setcap cap_net_raw,cap_net_admin+ep /usr/bin/tcpdump 2>/dev/null && echo "setcap tcpdump OK" || echo "setcap tcpdump SKIP"
[ -x /usr/bin/dumpcap ] && setcap cap_net_raw,cap_net_admin+ep /usr/bin/dumpcap 2>/dev/null
[ -x /usr/sbin/nft ] && setcap cap_net_admin+ep /usr/sbin/nft 2>/dev/null && echo "setcap nft OK"

# 2) sudoers: приложение w420 сможет `sudo -n nft ...` и `sudo -n tcpdump ...` без пароля навсегда
cat > /etc/sudoers.d/w420 <<'EOF'
# W420: passwordless для сетевых/патч-операций агента
thomas ALL=(root) NOPASSWD: /usr/sbin/nft, /usr/bin/tcpdump
thomas ALL=(root) NOPASSWD: /usr/bin/wg, /usr/bin/wg-quick, /usr/sbin/ip
thomas ALL=(root) NOPASSWD: /usr/bin/tee /etc/wireguard/w420wg.conf, /usr/bin/mkdir /etc/wireguard
thomas ALL=(root) NOPASSWD: /usr/bin/apt-get, /usr/bin/apt, /usr/bin/cat /var/log/apt/history.log
EOF
chmod 440 /etc/sudoers.d/w420
mkdir -p /etc/wireguard && chmod 700 /etc/wireguard
visudo -c -f /etc/sudoers.d/w420 && echo "sudoers OK"

# 3) Внешние пакеты (sidecar-инструменты плана эволюции)
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nmap suricata 2>&1 | tail -2 || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nmap 2>&1 | tail -2

# 4) Живая проверка механизма nft: применяем alert-таблицу атомарно, проверяем, снимаем (тест, не меняет политику)
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
if nft -f /tmp/w420_test.nft; then echo "NFT_APPLY_OK"; nft list table inet w420_em | head -10; nft delete table inet w420_em && echo "NFT_TEST_REVERTED"; else echo "NFT_APPLY_FAILED"; fi

# 5) Захват пакетов от обычного пользователя (через setcap, без sudo)
timeout 20 tcpdump -i any -c 10 -w /home/thomas/.w420/test_capture.pcap 2>/dev/null
if [ -s /home/thomas/.w420/test_capture.pcap ]; then echo "TCPDUMP_OK $(stat -c%s /home/thomas/.w420/test_capture.pcap) bytes"; else echo "TCPDUMP_FAILED"; fi

# 6) Права на данные w420
chown -R thomas:thomas /home/thomas/.w420

# 7) AppArmor: tcpdump по умолчанию может писать только в /tmp — разрешаем запись в ~/.w420
mkdir -p /etc/apparmor.d/local
cat > /etc/apparmor.d/local/usr.bin.tcpdump <<'EOF'
# W420: разрешить запись pcap в ~/.w420
owner /home/thomas/.w420/ r,
owner /home/thomas/.w420/** rwk,
EOF
apparmor_parser -r /etc/apparmor.d/usr.bin.tcpdump 2>/dev/null && echo "apparmor reloaded" || aa-reload /etc/apparmor.d/usr.bin.tcpdump 2>/dev/null || echo "apparmor reload SKIP (нужен рестарт профиля)"

echo "== DONE =="
