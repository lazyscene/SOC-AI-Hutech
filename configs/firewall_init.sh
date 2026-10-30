#!/bin/sh
echo "[+] Dang cau hinh Card mang LAN (ens37 -> 192.168.214.2/24)..."
# Xoa cac IP cu da gan truoc do de tranh xung dot
ip addr del 192.168.100.1/24 dev ens37 2>/dev/null || true
ip addr del 192.168.100.2/24 dev ens37 2>/dev/null || true
ip addr del 192.168.214.1/24 dev ens37 2>/dev/null || true

ip addr show ens37 | grep -q "192.168.214.2" || ip addr add 192.168.214.2/24 dev ens37
ip link set ens37 up

echo "[+] Bat IP Forwarding giua WAN (ens33) va Victim LAN (ens37)..."
sysctl -w net.ipv4.ip_forward=1

echo "[+] Thiet lap luat Iptables Baseline & NAT cho Victim..."
# Tao chain rieng de AI Agent chan IP ma khong anh huong luat goc
iptables -N AI_AGENT_BLOCK 2>/dev/null || iptables -F AI_AGENT_BLOCK
iptables -C FORWARD -j AI_AGENT_BLOCK 2>/dev/null || iptables -I FORWARD 1 -j AI_AGENT_BLOCK
iptables -C INPUT -j AI_AGENT_BLOCK 2>/dev/null || iptables -I INPUT 1 -j AI_AGENT_BLOCK

# Cho phep NAT de may Victim (192.168.214.x) di ra ngoai qua ens33
iptables -t nat -C POSTROUTING -s 192.168.214.0/24 -o ens33 -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -s 192.168.214.0/24 -o ens33 -j MASQUERADE

# Cho phep luu luong hop le qua Gateway
iptables -P FORWARD ACCEPT

echo "[+] Cap nhat bo luat Suricata Emerging Threats (neu chua co)..."
suricata-update --no-test --no-reload || true

echo "[+] Khoi chay Suricata Headless CLI giam sat ens37 va ens33..."
rm -f /var/run/suricata.pid
exec suricata -i ens37 -i ens33 --init-errors-fatal -l /var/log/suricata