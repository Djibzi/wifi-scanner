# host_discovery.py — Découverte des appareils sur le réseau
# Utilise ARP scan, ping sweep et résolution de noms

import subprocess
import re
import socket
import platform
import ipaddress
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.models import Host
from core.config import ScannerConfig


class OUILookup:
    # Identifie le fabricant d'un appareil à partir de son adresse MAC
    # Utilise les 3 premiers octets (OUI — Organizationally Unique Identifier)

    # Base locale des fabricants les plus courants
    OUI_DATABASE = {
        # Apple
        "00:1C:B3": "Apple", "3C:15:C2": "Apple", "A4:83:E7": "Apple",
        "AC:BC:32": "Apple", "F0:99:BF": "Apple", "DC:A4:CA": "Apple",
        "78:7B:8A": "Apple", "88:66:A5": "Apple", "C8:69:CD": "Apple",
        # Samsung
        "00:1A:8A": "Samsung", "54:92:BE": "Samsung", "AC:5F:3E": "Samsung",
        "C4:73:1E": "Samsung", "E4:7C:F9": "Samsung", "50:A4:D0": "Samsung",
        # Google
        "3C:5A:B4": "Google", "54:60:09": "Google", "F4:F5:D8": "Google",
        # Amazon
        "44:65:0D": "Amazon", "FC:65:DE": "Amazon", "68:54:FD": "Amazon",
        "A0:02:DC": "Amazon", "74:C2:46": "Amazon",
        # Raspberry Pi
        "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
        # Espressif (ESP32/ESP8266)
        "30:AE:A4": "Espressif", "24:6F:28": "Espressif", "A4:CF:12": "Espressif",
        # Intel
        "00:1E:64": "Intel", "3C:97:0E": "Intel", "8C:8D:28": "Intel",
        # TP-Link
        "50:C7:BF": "TP-Link", "C0:25:E9": "TP-Link", "14:CC:20": "TP-Link",
        # Netgear
        "00:14:6C": "Netgear", "C4:04:15": "Netgear", "B0:B9:8A": "Netgear",
        # Huawei
        "00:1E:10": "Huawei", "48:46:FB": "Huawei", "70:8A:09": "Huawei",
        # Philips (Hue)
        "00:17:88": "Philips Lighting",
        # Sonos
        "00:0E:58": "Sonos", "54:2A:1B": "Sonos",
        # Microsoft
        "00:15:5D": "Microsoft", "00:50:F2": "Microsoft",
        # Dell
        "00:14:22": "Dell", "18:03:73": "Dell",
        # HP
        "00:1A:4B": "HP", "3C:D9:2B": "HP",
        # Synology
        "00:11:32": "Synology",
        # QNAP
        "00:08:9B": "QNAP",
        # Xiaomi
        "28:6C:07": "Xiaomi", "64:CC:2E": "Xiaomi", "78:11:DC": "Xiaomi",
        # ZTE (Box opérateur)
        "FC:F5:28": "ZTE", "00:1E:73": "ZTE",
        # Freebox
        "00:07:CB": "Freebox", "14:0C:76": "Freebox", "F4:CA:E5": "Freebox",
        # Livebox (Orange)
        "E8:AD:A6": "Sagemcom (Livebox)", "A4:4B:15": "Sagemcom (Livebox)",
        # SFR Box
        "00:1F:9F": "SFR", "C8:0E:14": "Technicolor (SFR)",
        # Bouygues
        "F8:08:4F": "Sercomm (Bbox)",
    }

    def lookup(self, mac):
        # Cherche le fabricant à partir de l'adresse MAC
        if not mac:
            return ""

        # Normaliser le format MAC (AA:BB:CC:DD:EE:FF)
        mac_clean = mac.upper().replace("-", ":")
        prefix = mac_clean[:8]

        return self.OUI_DATABASE.get(prefix, "")

    def guess_device_type(self, vendor, open_ports=None):
        # Devine le type d'appareil à partir du fabricant et des ports ouverts
        if not vendor:
            return "Inconnu"

        vendor_lower = vendor.lower()
        open_ports = open_ports or []

        # Routeurs / Box opérateur
        if any(kw in vendor_lower for kw in ["freebox", "livebox", "sagemcom", "sfr",
                                               "bbox", "sercomm", "zte", "netgear",
                                               "tp-link", "huawei"]):
            if 80 in open_ports or 443 in open_ports:
                return "Routeur"

        # IoT
        if any(kw in vendor_lower for kw in ["espressif", "raspberry", "philips lighting",
                                               "sonos", "xiaomi"]):
            return "IoT"

        # Apple
        if "apple" in vendor_lower:
            if 62078 in open_ports:
                return "iPhone/iPad"
            return "Apple (Mac/iPhone)"

        # Samsung
        if "samsung" in vendor_lower:
            if 8001 in open_ports or 55000 in open_ports:
                return "Smart TV Samsung"
            return "Samsung (Tel/TV)"

        # Amazon
        if "amazon" in vendor_lower:
            return "Amazon Echo/Fire"

        # Google
        if "google" in vendor_lower:
            return "Google (Chromecast/Nest)"

        # NAS
        if any(kw in vendor_lower for kw in ["synology", "qnap"]):
            return "NAS"

        # PC / Serveur
        if any(kw in vendor_lower for kw in ["intel", "dell", "hp", "microsoft"]):
            return "PC"

        return "Inconnu"


class HostDiscovery:
    # Découvre tous les appareils connectés au réseau local

    def __init__(self, config=None, logger=None):
        self.config = config or ScannerConfig()
        self.logger = logger
        self.os_type = platform.system()
        self.oui = OUILookup()

    def discover(self, gateway_ip=None, subnet_mask=None):
        # Lance la découverte des hôtes sur le réseau
        # Retourne une liste d'objets Host

        # Déterminer le réseau à scanner
        network = self._get_network(gateway_ip, subnet_mask)
        if not network:
            if self.logger:
                self.logger.error("Impossible de déterminer le réseau à scanner")
            return []

        if self.logger:
            self.logger.info(f"Scan du réseau : {network}")

        hosts = {}

        # Méthode 1 : Table ARP du système (instantané, appareils déjà connus)
        arp_table_hosts = self._read_arp_table()
        for h in arp_table_hosts:
            # Filtrer les hôtes hors du réseau scanné
            try:
                if ipaddress.IPv4Address(h.ip) in network:
                    hosts[h.ip] = h
            except ValueError:
                pass

        if self.logger:
            self.logger.info(f"{len(hosts)} hôte(s) dans la table ARP")

        # Méthode 2 : Ping sweep (découvre les hôtes qui répondent au ping)
        ping_hosts = self._ping_sweep(network)
        for h in ping_hosts:
            if h.ip not in hosts:
                hosts[h.ip] = h

        # Méthode 3 : Scan ARP avec scapy (le plus fiable en LAN, nécessite admin)
        arp_hosts = self._arp_scan(network)
        for h in arp_hosts:
            if h.ip not in hosts:
                hosts[h.ip] = h
            elif not hosts[h.ip].mac and h.mac:
                # Compléter le MAC si manquant
                hosts[h.ip].mac = h.mac

        # Relire la table ARP après le ping sweep (le ping a pu la remplir)
        arp_table_after = self._read_arp_table()
        for h in arp_table_after:
            if h.ip in hosts and not hosts[h.ip].mac and h.mac:
                hosts[h.ip].mac = h.mac

        # Résolution DNS inverse en parallèle (c'est l'opération la plus lente)
        self._batch_reverse_dns(list(hosts.values()))

        # Enrichir chaque hôte (vendor, device type, OS guess)
        for host in hosts.values():
            self._enrich_host(host, gateway_ip)
            if self.logger:
                self.logger.host_found(host.ip, host.mac, host.vendor)

        if self.logger:
            self.logger.info(f"{len(hosts)} hôte(s) découvert(s)")

        return list(hosts.values())

    # --- Méthodes de découverte ---

    def _arp_scan(self, network):
        # Scan ARP avec scapy (le plus fiable en réseau local)
        hosts = []
        try:
            from scapy.all import ARP, Ether, srp, conf
            conf.verb = 0  # Mode silencieux

            # Construire et envoyer les requêtes ARP
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
            answered, _ = srp(arp_request, timeout=self.config.timeout * 4, retry=1)

            for sent, received in answered:
                host = Host(
                    ip=received.psrc,
                    mac=received.hwsrc.upper(),
                )
                hosts.append(host)

        except ImportError:
            if self.logger:
                self.logger.warning("scapy non installé — scan ARP désactivé")
        except PermissionError:
            if self.logger:
                self.logger.warning("Droits insuffisants pour le scan ARP (nécessite admin/root)")
        except Exception as e:
            if self.logger:
                self.logger.error(f"Erreur scan ARP : {e}")

        return hosts

    def _ping_sweep(self, network):
        # Ping sweep multi-threadé avec timeout court
        hosts = []
        ips = [str(ip) for ip in ipaddress.IPv4Network(network, strict=False).hosts()]

        # Limiter le nombre d'IP si le réseau est trop grand
        if len(ips) > 1024:
            if self.logger:
                self.logger.warning(f"Réseau trop grand ({len(ips)} IPs), limité aux 1024 premières")
            ips = ips[:1024]

        if self.logger:
            self.logger.info(f"Ping sweep de {len(ips)} IPs...")

        # Sur Windows, utiliser un timeout très court (500ms)
        timeout_ms = 500 if self.os_type == "Windows" else int(self.config.timeout * 1000)

        with ThreadPoolExecutor(max_workers=min(150, len(ips))) as executor:
            futures = {executor.submit(self._ping_host, ip, timeout_ms): ip for ip in ips}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    hosts.append(result)

        return hosts

    def _ping_host(self, ip, timeout_ms=500):
        # Ping un seul hôte et retourne un Host si réponse
        try:
            if self.os_type == "Windows":
                cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
            else:
                cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]

            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=(timeout_ms / 1000) + 1,
                creationflags=0x08000000 if self.os_type == "Windows" else 0  # CREATE_NO_WINDOW
            )

            if result.returncode == 0:
                # Vérifier qu'il y a bien un TTL dans la réponse (évite les faux positifs Windows)
                match = re.search(r"TTL[=:](\d+)", result.stdout, re.IGNORECASE)
                if match:
                    ttl = int(match.group(1))
                    return Host(ip=ip, ttl=ttl)

        except (subprocess.TimeoutExpired, Exception):
            pass

        return None

    def _read_arp_table(self):
        # Lit la table ARP du système
        hosts = []
        try:
            if self.os_type == "Windows":
                result = subprocess.run(
                    ["arp", "-a"],
                    capture_output=True, text=True, timeout=10, encoding="cp850"
                )
            else:
                result = subprocess.run(
                    ["arp", "-a"],
                    capture_output=True, text=True, timeout=10
                )

            # Parser les entrées ARP
            # Windows : 192.168.1.1     aa-bb-cc-dd-ee-ff     dynamique
            # Linux   : hostname (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
            for line in result.stdout.split("\n"):
                if self.os_type == "Windows":
                    match = re.search(r"([\d.]+)\s+([\da-fA-F-]{17})\s+(\w+)", line)
                    if match and match.group(3).lower() in ["dynamique", "dynamic"]:
                        mac = match.group(2).replace("-", ":").upper()
                        hosts.append(Host(ip=match.group(1), mac=mac))
                else:
                    match = re.search(r"\(([\d.]+)\)\s+at\s+([\da-fA-F:]{17})", line)
                    if match:
                        hosts.append(Host(ip=match.group(1), mac=match.group(2).upper()))

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return hosts

    # --- Enrichissement des hôtes ---

    def _batch_reverse_dns(self, hosts):
        # Résolution DNS inverse en parallèle avec timeout
        def resolve(host):
            try:
                hostname, _, _ = socket.gethostbyaddr(host.ip)
                host.hostname = hostname
            except (socket.herror, socket.gaierror, OSError):
                pass

        with ThreadPoolExecutor(max_workers=min(30, len(hosts))) as executor:
            executor.map(resolve, hosts)

    def _enrich_host(self, host, gateway_ip=None):
        # Enrichit un hôte avec le fabricant et le type d'appareil

        # OUI lookup (fabricant)
        if host.mac:
            host.vendor = self.oui.lookup(host.mac)

        # Détection gateway
        if gateway_ip and host.ip == gateway_ip:
            host.is_gateway = True
            host.device_type = "Routeur/Gateway"
        else:
            host.device_type = self.oui.guess_device_type(host.vendor)

        # Estimation OS basée sur le TTL
        if host.ttl > 0:
            host.os_guess = self._guess_os_from_ttl(host.ttl)

    def _guess_os_from_ttl(self, ttl):
        # Estimation du système d'exploitation basée sur le TTL
        # Les TTL diminuent à chaque saut, on cherche le TTL initial le plus proche
        if ttl <= 64:
            return "Linux/macOS/Android"
        elif ttl <= 128:
            return "Windows"
        else:
            return "Routeur/Switch"

    # --- Utilitaires réseau ---

    def _get_network(self, gateway_ip=None, subnet_mask=None):
        # Détermine le réseau à scanner
        if gateway_ip and subnet_mask:
            try:
                # Calculer le réseau à partir de la gateway et du masque
                network = ipaddress.IPv4Network(f"{gateway_ip}/{subnet_mask}", strict=False)
                return network
            except ValueError:
                pass

        # Fallback : détecter automatiquement
        return self._detect_network()

    def _detect_network(self):
        # Détecte automatiquement le réseau local
        try:
            if self.os_type == "Windows":
                result = subprocess.run(
                    ["ipconfig"],
                    capture_output=True, text=True, timeout=10, encoding="cp850"
                )
                output = result.stdout

                # Trouver la section WiFi
                sections = re.split(r"\r?\n(?=\S)", output)
                for section in sections:
                    if any(kw in section.lower() for kw in ["wi-fi", "wifi", "wireless", "sans fil"]):
                        ip_match = re.search(r"(?:IPv4|Adresse IP).*?:\s*([\d.]+)", section)
                        mask_match = re.search(r"(?:Masque|Mask).*?:\s*([\d.]+)", section)
                        if ip_match and mask_match:
                            return ipaddress.IPv4Network(
                                f"{ip_match.group(1)}/{mask_match.group(1)}", strict=False
                            )
            else:
                result = subprocess.run(
                    ["ip", "-o", "addr", "show"],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.split("\n"):
                    if "wl" in line:
                        match = re.search(r"inet ([\d.]+/\d+)", line)
                        if match:
                            return ipaddress.IPv4Network(match.group(1), strict=False)
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
            pass

        # Dernier recours : réseau par défaut courant
        if self.logger:
            self.logger.warning("Détection automatique échouée, utilisation de 192.168.1.0/24")
        return ipaddress.IPv4Network("192.168.1.0/24")
