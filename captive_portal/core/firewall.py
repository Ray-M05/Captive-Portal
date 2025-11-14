# core/firewall.py

import subprocess
from typing import Optional


def run_cmd(cmd: list[str]) -> None:
    """Ejecuta un comando del sistema y lanza excepción si falla."""
    subprocess.run(cmd, check=True)


class FirewallManager:
    """
    Encapsula las operaciones de firewall para el portal cautivo.
    Usa iptables desde Python (sin librerías externas).
    """

    def __init__(
        self,
        lan_iface: str = "wlo1",
        wan_iface: str = "usb0",
        lan_net: str = "10.42.0.0/24",
    ) -> None:
        self.lan_iface = lan_iface
        self.wan_iface = wan_iface
        self.lan_net = lan_net

    # --- Inicialización global (equivalente al bootstrap script) ---

    def setup_base_rules(self) -> None:
        """Configura las reglas base del portal (bloqueo por defecto)."""
        # Habilitar forwarding
        run_cmd(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"])

        # Limpiar reglas
        run_cmd(["sudo", "iptables", "-F"])
        run_cmd(["sudo", "iptables", "-t", "nat", "-F"])
        run_cmd(["sudo", "iptables", "-X"])

        # Políticas por defecto
        run_cmd(["sudo", "iptables", "-P", "INPUT", "ACCEPT"])
        run_cmd(["sudo", "iptables", "-P", "OUTPUT", "ACCEPT"])
        run_cmd(["sudo", "iptables", "-P", "FORWARD", "DROP"])

        # Permitir tráfico ya establecido
        run_cmd([
            "sudo", "iptables", "-A", "FORWARD",
            "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
            "-j", "ACCEPT",
        ])

        # NAT (masquerade)
        run_cmd([
            "sudo", "iptables", "-t", "nat", "-A", "POSTROUTING",
            "-o", self.wan_iface,
            "-j", "MASQUERADE",
        ])

    # --- Operaciones por cliente ---

    def allow_client(self, client_ip: str) -> None:
        """
        Permite que la IP del cliente pueda enrutar tráfico hacia Internet.
        Implementado como regla iptables en la cadena FORWARD.
        """
        # Regla: si viene desde client_ip por la LAN, se acepta (se inserta al principio)
        run_cmd([
            "sudo", "iptables", "-I", "FORWARD", "1",
            "-s", client_ip,
            "-i", self.lan_iface,
            "-j", "ACCEPT",
        ])

    def block_client(self, client_ip: str) -> None:
        """
        Elimina reglas de FORWARD que permitan a esta IP (para un logout, por ejemplo).
        """
        # Esto es un poco bruto: borra cualquier regla con -s client_ip en FORWARD.
        # Para el proyecto es más que suficiente.
        while True:
            result = subprocess.run(
                ["sudo", "iptables", "-D", "FORWARD", "-s", client_ip, "-j", "ACCEPT"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                # No quedan reglas por borrar
                break

    # --- Limpieza global ---

    def teardown(self) -> None:
        """Limpia todas las reglas (similar al teardown script)."""
        run_cmd(["sudo", "iptables", "-F"])
        run_cmd(["sudo", "iptables", "-t", "nat", "-F"])
        run_cmd(["sudo", "iptables", "-X"])

        run_cmd(["sudo", "iptables", "-P", "INPUT", "ACCEPT"])
        run_cmd(["sudo", "iptables", "-P", "OUTPUT", "ACCEPT"])
        run_cmd(["sudo", "iptables", "-P", "FORWARD", "ACCEPT"])

        # Opcional: deshabilitar forwarding
        subprocess.run(
            ["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"],
            check=False,
        )
