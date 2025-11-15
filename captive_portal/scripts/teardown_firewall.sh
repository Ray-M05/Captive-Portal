set -e

echo "[*] Limpiando reglas de iptables..."
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -X

echo "[*] Restaurando políticas permisivas..."
sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -P FORWARD ACCEPT

echo "[*] (Opcional) Deshabilitar reenvío IP..."
sudo sysctl -w net.ipv4.ip_forward=0 > /dev/null || true

echo "[*] Firewall desmontado."
