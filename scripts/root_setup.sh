#!/usr/bin/env bash
# root_setup.sh — W420 root setup. Запускается ТОЛЬКО пользователем от своего имени (sudo);
# пароль никуда не передаётся, скрипт интерактивный и безопасен.
set -uo pipefail
echo "== W420 root setup $(date) =="; echo

# 1) Capabilities — tcpdump/dumpcap захватывают пакеты БЕЗ sudo, nft — через CapNetAdmin
setcap cap_net_raw,cap_net_admin+ep /usr/bin/tcpdump 2>/dev/null && echo "setcap tcpdump OK" || echo "setcap tcpdump SKIP"
[ -x /usr/bin/dumpcap ] && setcap cap_net_raw,cap_net_admin+ep /usr/bin/dumpcap 2>/dev/null
[ -x /usr/sbin/nft ] && setcap cap_net_admin+ep /usr/sbin/nft 2>/dev/null && echo "setcap nft OK"

# 2) sudoers: МИНИМАЛЬНЫЙ passwordless-набор (security-аудит 13.11.2026).
#    - nft/tcpdump работают через setcap cap_net_admin/cap_net_raw (шаг 1) — sudoers-права не нужны.
#    - wg-quick не используется кодом (есть wg setconf + ip с фикс. аргументами) — убран.
#    - apt-get install — ТОЛЬКО через root-хелпер w420-apt-install, валидирующий имена пакетов.
#    - tee — только в фиксированный /etc/wireguard/w420wg.conf (контент — чистый wg setconf, без PostUp).
cat > /usr/local/sbin/w420-apt-install <<'HELPER'
#!/usr/bin/env bash
# w420-apt-install — единственный passwordless-путь установки пакетов для W420.
# Валидирует имена (только [a-z0-9.+-], 1..50 аргументов) и зовёт apt-get install.
set -euo pipefail
if [ $# -lt 1 ] || [ $# -gt 50 ]; then echo "usage: w420-apt-install <pkg...> (1..50)" >&2; exit 2; fi
for p in "$@"; do
  if ! [[ "$p" =~ ^[a-z0-9][a-z0-9.+-]{0,63}$ ]]; then echo "отклонено имя пакета: $p" >&2; exit 2; fi
done
exec /usr/bin/apt-get install -y -- "$@"
HELPER
chmod 755 /usr/local/sbin/w420-apt-install

cat > /etc/sudoers.d/w420 <<'EOF'
# W420: минимальный passwordless-набор (аудит 13.11.2026). Не расширять без аудита!
thomas ALL=(root) NOPASSWD: /usr/bin/wg show *
thomas ALL=(root) NOPASSWD: /usr/bin/wg setconf w420wg /etc/wireguard/w420wg.conf
thomas ALL=(root) NOPASSWD: /usr/sbin/ip link add w420wg type wireguard, /usr/sbin/ip address add 10.77.0.1/24 dev w420wg, /usr/sbin/ip link set up dev w420wg, /usr/sbin/ip link set down dev w420wg, /usr/sbin/ip link delete dev w420wg
thomas ALL=(root) NOPASSWD: /usr/bin/tee /etc/wireguard/w420wg.conf
thomas ALL=(root) NOPASSWD: /usr/bin/apt-get update, /usr/local/sbin/w420-apt-install *, /usr/bin/cat /var/log/apt/history.log
EOF
chmod 440 /etc/sudoers.d/w420
visudo -c -f /etc/sudoers.d/w420 >/dev/null 2>&1 && echo "sudoers OK" || echo "sudoers CHECK_FAILED"
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
