# port_scanner.py — Scan de ports TCP/UDP
# Implémente le TCP Connect Scan multi-threadé et le SYN Scan (scapy)

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.models import Host, Port, PortState, Protocol
from core.config import ScannerConfig


class PortScanner:
    # Scanne les ports ouverts sur les hôtes découverts

    def __init__(self, config=None, logger=None):
        self.config = config or ScannerConfig()
        self.logger = logger

    def scan_hosts(self, hosts):
        # Scanne les ports de tous les hôtes
        ports_to_scan = self.config.get_ports_to_scan()

        if self.logger:
            self.logger.info(f"Scan de {len(ports_to_scan)} ports sur {len(hosts)} hôte(s)")

        for host in hosts:
            self._scan_host(host, ports_to_scan)

        return hosts

    def scan_single_host(self, host, ports=None):
        # Scanne les ports d'un seul hôte
        ports_to_scan = ports or self.config.get_ports_to_scan()
        self._scan_host(host, ports_to_scan)
        return host

    def _scan_host(self, host, ports):
        # Scanne les ports TCP d'un hôte avec multi-threading
        if self.logger:
            self.logger.info(f"Scan de {host.ip} ({len(ports)} ports)...")

        open_ports = []

        with ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
            futures = {
                executor.submit(self._tcp_connect, host.ip, port): port
                for port in ports
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)

        # Trier par numéro de port
        open_ports.sort(key=lambda p: p.number)
        host.open_ports = open_ports

        # Mettre à jour le dict services
        for port in open_ports:
            service_name = self.config.get_port_name(port.number)
            host.services[port.number] = service_name
            port.service = service_name

        if self.logger:
            if open_ports:
                port_list = ", ".join(str(p.number) for p in open_ports)
                self.logger.info(f"{host.ip} — {len(open_ports)} port(s) ouvert(s) : {port_list}")
            else:
                self.logger.info(f"{host.ip} — aucun port ouvert")

    def _tcp_connect(self, ip, port):
        # TCP Connect Scan — tente une connexion complète
        # Retourne un objet Port si ouvert, None sinon
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.config.timeout)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                return Port(
                    number=port,
                    protocol=Protocol.TCP,
                    state=PortState.OPEN,
                )
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()
        return None

    def scan_udp(self, host, ports=None):
        # Scan UDP basique — envoie un datagramme vide et attend la réponse
        # Moins fiable que TCP (pas de confirmation de réception)
        udp_ports = ports or [53, 67, 68, 123, 161, 162, 500, 1900, 5353]

        if self.logger:
            self.logger.info(f"Scan UDP de {host.ip} ({len(udp_ports)} ports)...")

        for port in udp_ports:
            result = self._udp_probe(host.ip, port)
            if result:
                host.open_ports.append(result)
                host.services[port] = self.config.get_port_name(port)

    def _udp_probe(self, ip, port):
        # Envoie un paquet UDP et vérifie la réponse
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.config.timeout * 2)
        try:
            # Envoyer un paquet vide (ou adapté au protocole)
            payload = self._get_udp_payload(port)
            sock.sendto(payload, (ip, port))
            data, _ = sock.recvfrom(1024)
            if data:
                return Port(
                    number=port,
                    protocol=Protocol.UDP,
                    state=PortState.OPEN,
                    banner=data[:100].decode("utf-8", errors="replace"),
                )
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()
        return None

    def _get_udp_payload(self, port):
        # Retourne un payload adapté au protocole UDP
        # Certains services ne répondent qu'à des requêtes spécifiques
        if port == 53:
            # Requête DNS basique (query pour "version.bind")
            return (b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                    b"\x07version\x04bind\x00\x00\x10\x00\x03")
        elif port == 161:
            # SNMP GET community "public"
            return (b"\x30\x26\x02\x01\x01\x04\x06public"
                    b"\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00"
                    b"\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06"
                    b"\x01\x02\x01\x05\x00")
        elif port == 1900:
            # SSDP M-SEARCH
            return (b"M-SEARCH * HTTP/1.1\r\n"
                    b"HOST: 239.255.255.250:1900\r\n"
                    b"MAN: \"ssdp:discover\"\r\n"
                    b"MX: 1\r\n"
                    b"ST: ssdp:all\r\n\r\n")
        # Payload vide par défaut
        return b"\x00"
