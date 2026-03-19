# traffic_analyzer.py — Analyse passive du trafic réseau
# Écoute le trafic sans envoyer de paquets (mode promiscuous)
# Détecte les protocoles non chiffrés, anomalies ARP, appareils bavards

import time
import re
import socket
import struct
from collections import defaultdict

from core.models import Vulnerability, Severity
from core.config import ScannerConfig


class TrafficAnalyzer:
    # Analyse passive du trafic réseau

    def __init__(self, config=None, logger=None, duration=30):
        self.config = config or ScannerConfig()
        self.logger = logger
        self.duration = duration  # Durée d'écoute en secondes

        # Statistiques collectées
        self.packets_count = 0
        self.arp_table = {}              # IP -> MAC (pour détecter les changements)
        self.arp_anomalies = []          # Changements IP/MAC suspects
        self.protocols_seen = defaultdict(int)  # Protocole -> nombre de paquets
        self.unencrypted = []            # Protocoles non chiffrés détectés
        self.dns_queries = defaultdict(list)    # IP source -> [domaines requêtés]
        self.traffic_by_host = defaultdict(int) # IP -> octets
        self.vulnerabilities = []

    def analyze(self, duration=None):
        # Lance l'écoute passive pendant la durée spécifiée
        listen_time = duration or self.duration

        if self.logger:
            self.logger.info(f"Écoute passive du trafic pendant {listen_time}s...")

        # Tenter l'écoute avec scapy (meilleure option)
        if self._analyze_with_scapy(listen_time):
            pass
        else:
            # Fallback : écoute avec socket raw
            self._analyze_with_raw_socket(listen_time)

        # Générer les vulnérabilités à partir des observations
        self._generate_vulnerabilities()

        if self.logger:
            self.logger.info(f"Écoute terminée : {self.packets_count} paquets capturés")
            self.logger.info(f"{len(self.vulnerabilities)} anomalie(s) détectée(s)")

        return self.vulnerabilities

    # --- Analyse avec scapy ---

    def _analyze_with_scapy(self, duration):
        # Utilise scapy pour l'écoute passive
        try:
            from scapy.all import sniff, ARP, DNS, DNSQR, IP, TCP, UDP, Raw, conf
            conf.verb = 0
        except ImportError:
            if self.logger:
                self.logger.warning("scapy non installé — écoute avec socket raw")
            return False

        try:
            def process_packet(pkt):
                self.packets_count += 1

                # Analyser les paquets ARP
                if pkt.haslayer(ARP):
                    self._process_arp_scapy(pkt)

                # Analyser les paquets IP
                if pkt.haslayer(IP):
                    src_ip = pkt[IP].src
                    self.traffic_by_host[src_ip] += len(pkt)

                    # Détecter les protocoles non chiffrés
                    if pkt.haslayer(TCP):
                        dport = pkt[TCP].dport
                        sport = pkt[TCP].sport
                        self._check_unencrypted_tcp(src_ip, sport, dport, pkt)

                    # Analyser les requêtes DNS
                    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                        domain = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
                        self.dns_queries[src_ip].append(domain)

            sniff(timeout=duration, prn=process_packet, store=False)
            return True

        except PermissionError:
            if self.logger:
                self.logger.warning("Droits insuffisants pour le sniffing (nécessite admin/root)")
            return False
        except Exception as e:
            if self.logger:
                self.logger.error(f"Erreur scapy : {e}")
            return False

    def _process_arp_scapy(self, pkt):
        # Traite un paquet ARP et détecte les anomalies
        from scapy.all import ARP
        if pkt[ARP].op == 2:  # ARP Reply
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc.upper()

            if ip in self.arp_table:
                old_mac = self.arp_table[ip]
                if old_mac != mac:
                    # Changement de MAC pour la même IP — possible ARP spoofing
                    self.arp_anomalies.append({
                        "ip": ip,
                        "old_mac": old_mac,
                        "new_mac": mac,
                        "timestamp": time.time(),
                    })
            self.arp_table[ip] = mac

    def _check_unencrypted_tcp(self, src_ip, sport, dport, pkt):
        # Détecte les protocoles non chiffrés
        from scapy.all import Raw

        unencrypted_ports = {
            80: "HTTP",
            21: "FTP",
            23: "Telnet",
            25: "SMTP",
            110: "POP3",
            143: "IMAP",
            1883: "MQTT",
        }

        port = dport if dport in unencrypted_ports else (sport if sport in unencrypted_ports else None)
        if port and port in unencrypted_ports:
            proto = unencrypted_ports[port]
            if proto not in [u["protocol"] for u in self.unencrypted]:
                self.unencrypted.append({
                    "protocol": proto,
                    "port": port,
                    "source_ip": src_ip,
                })
                self.protocols_seen[proto] += 1

    # --- Analyse avec socket raw (fallback) ---

    def _analyze_with_raw_socket(self, duration):
        # Écoute avec socket raw (Windows/Linux)
        try:
            import platform
            if platform.system() == "Windows":
                # Windows : socket raw avec SIO_RCVALL
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                # Récupérer l'IP locale
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                sock.bind((local_ip, 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                # Activer le mode promiscuous
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

            sock.settimeout(1)
            end_time = time.time() + duration

            while time.time() < end_time:
                try:
                    data = sock.recv(65535)
                    if data:
                        self.packets_count += 1
                        self._process_raw_packet(data)
                except socket.timeout:
                    continue

            if platform.system() == "Windows":
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sock.close()

        except PermissionError:
            if self.logger:
                self.logger.warning("Droits insuffisants pour le sniffing raw socket")
        except Exception as e:
            if self.logger:
                self.logger.error(f"Erreur socket raw : {e}")

    def _process_raw_packet(self, data):
        # Parse basique d'un paquet IP brut
        if len(data) < 20:
            return

        # Header IP
        iph = struct.unpack("!BBHHHBBH4s4s", data[:20])
        protocol = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])

        self.traffic_by_host[src_ip] += len(data)

        ihl = (iph[0] & 0xF) * 4

        # TCP
        if protocol == 6 and len(data) >= ihl + 20:
            tcp_header = struct.unpack("!HH", data[ihl:ihl + 4])
            sport, dport = tcp_header

            unencrypted_ports = {80: "HTTP", 21: "FTP", 23: "Telnet",
                                 25: "SMTP", 110: "POP3", 143: "IMAP", 1883: "MQTT"}
            for port_num, proto in unencrypted_ports.items():
                if sport == port_num or dport == port_num:
                    if proto not in [u["protocol"] for u in self.unencrypted]:
                        self.unencrypted.append({
                            "protocol": proto,
                            "port": port_num,
                            "source_ip": src_ip,
                        })
                    break

        # UDP (port 53 = DNS)
        elif protocol == 17 and len(data) >= ihl + 8:
            udp_header = struct.unpack("!HH", data[ihl:ihl + 4])
            sport, dport = udp_header
            if dport == 53:
                self.protocols_seen["DNS"] += 1

    # --- Génération des vulnérabilités ---

    def _generate_vulnerabilities(self):
        # Convertit les observations en vulnérabilités

        # ARP Spoofing détecté
        if self.arp_anomalies:
            for anomaly in self.arp_anomalies:
                self.vulnerabilities.append(Vulnerability(
                    name=f"Possible ARP Spoofing détecté sur {anomaly['ip']}",
                    severity=Severity.CRITICAL,
                    description=f"L'adresse MAC associée à {anomaly['ip']} a changé de "
                               f"{anomaly['old_mac']} à {anomaly['new_mac']}. "
                               "Cela peut indiquer une attaque ARP spoofing en cours.",
                    remediation="Vérifier les appareils sur le réseau. Activer le Dynamic ARP "
                               "Inspection (DAI) si le switch le supporte. Utiliser un VPN.",
                    host_ip=anomaly["ip"],
                    proof=f"MAC changé : {anomaly['old_mac']} → {anomaly['new_mac']}",
                ))

        # Protocoles non chiffrés
        for proto_info in self.unencrypted:
            self.vulnerabilities.append(Vulnerability(
                name=f"Trafic {proto_info['protocol']} non chiffré détecté",
                severity=Severity.MEDIUM,
                description=f"Du trafic {proto_info['protocol']} (port {proto_info['port']}) a été "
                           "détecté en clair sur le réseau. Les données transmises sont lisibles "
                           "par n'importe quel appareil sur le même réseau.",
                remediation=f"Utiliser la version chiffrée du protocole "
                           f"({self._get_encrypted_alternative(proto_info['protocol'])}).",
                host_ip=proto_info["source_ip"],
                port=proto_info["port"],
            ))

        # Appareils bavards (plus de 1 Mo de trafic pendant l'écoute)
        for ip, bytes_count in self.traffic_by_host.items():
            if bytes_count > 1_000_000:
                self.vulnerabilities.append(Vulnerability(
                    name=f"Appareil bavard : {ip} ({bytes_count // 1024} Ko)",
                    severity=Severity.INFO,
                    description=f"L'appareil {ip} a généré {bytes_count // 1024} Ko de trafic "
                               f"pendant les {self.duration}s d'écoute.",
                    remediation="Vérifier si ce volume de trafic est normal pour cet appareil.",
                    host_ip=ip,
                ))

    def _get_encrypted_alternative(self, protocol):
        # Retourne l'alternative chiffrée d'un protocole
        alternatives = {
            "HTTP": "HTTPS (port 443)",
            "FTP": "SFTP (SSH) ou FTPS",
            "Telnet": "SSH (port 22)",
            "SMTP": "SMTPS (port 465/587)",
            "POP3": "POP3S (port 995)",
            "IMAP": "IMAPS (port 993)",
            "MQTT": "MQTT-TLS (port 8883)",
        }
        return alternatives.get(protocol, "version TLS du protocole")

    def get_summary(self):
        # Retourne un résumé de l'analyse
        return {
            "packets": self.packets_count,
            "arp_anomalies": len(self.arp_anomalies),
            "unencrypted_protocols": [u["protocol"] for u in self.unencrypted],
            "dns_queries_count": sum(len(q) for q in self.dns_queries.values()),
            "top_talkers": sorted(
                self.traffic_by_host.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10],
            "vulnerabilities": len(self.vulnerabilities),
        }
