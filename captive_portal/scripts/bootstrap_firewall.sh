set -e

LAN_IFACE="${1:-wlo1}"      # interfaz del AP
WAN_IFACE="${2:-usb0}"      # interfaz hacia Internet (módem USB)
LAN_NET="${3:-10.42.0.0/24}" # red del hotspot (NetworkManager suele usar 10.42.0.0/24)

echo "[*] Habilitando reenvío IP..."
sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null

echo "[*] Limpiando reglas previas..."
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -X

echo "[*] Estableciendo políticas por defecto..."
sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -P FORWARD DROP   # clave: bloquear forwarding por defecto

echo "[*] Permitimos tráfico establecido/relacionado..."
sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "[*] Configurando NAT (masquerade) hacia Internet..."
sudo iptables -t nat -A POSTROUTING -o "$WAN_IFACE" -j MASQUERADE

echo "[*] Firewall base del portal cautivo inicializado."
