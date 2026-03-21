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
        "8C:97:EA": "Freebox",
        # Livebox (Orange)
        "E8:AD:A6": "Sagemcom (Livebox)", "A4:4B:15": "Sagemcom (Livebox)",
        # SFR Box
        "00:1F:9F": "SFR", "C8:0E:14": "Technicolor (SFR)",
        # Bouygues
        "F8:08:4F": "Sercomm (Bbox)",
        # LG
        "00:AA:70": "LG", "C4:9A:02": "LG", "A8:23:FE": "LG",
        # Sony
        "00:04:1F": "Sony", "AC:9B:0A": "Sony", "04:5D:4B": "Sony",
        # Lenovo
        "00:06:1B": "Lenovo", "28:D2:44": "Lenovo", "50:7B:9D": "Lenovo",
        # ASUS
        "00:0C:6E": "ASUS", "2C:4D:54": "ASUS", "AC:22:05": "ASUS",
        # OnePlus
        "94:65:2D": "OnePlus", "C0:EE:FB": "OnePlus",
        # OPPO
        "2C:5B:E1": "OPPO", "A4:3B:FA": "OPPO",
        # Realme
        "FE:3E:E8": "Realme",
        # Honor
        "60:F2:62": "Honor",
        # Motorola
        "00:0A:28": "Motorola", "9C:D9:17": "Motorola",
        # Roku
        "B0:A7:37": "Roku", "D0:4D:C6": "Roku",
        # Ring (Amazon)
        "00:62:6E": "Ring (Amazon)",
        # Wyze
        "2C:AA:8E": "Wyze",
        # Nest (Google)
        "18:B4:30": "Nest (Google)", "64:16:66": "Nest (Google)",
        # Bose
        "04:52:C7": "Bose", "08:DF:1F": "Bose",
        # Nintendo
        "00:1F:32": "Nintendo", "E0:0C:7F": "Nintendo", "98:B6:E9": "Nintendo",
        # Liteon / Realtek (composant WiFi courant)
        "5C:5F:67": "Liteon/PC",
        # Vestel (TV, décodeurs, objets connectés)
        "A8:08:CF": "Vestel", "00:1A:E8": "Vestel",
        # Tuya (IoT smart home)
        "D8:F1:5B": "Tuya", "50:8A:06": "Tuya",
        # Shenzhen (IoT chinois divers)
        "B4:E6:2D": "Shenzhen/IoT",
        # TCL / Thomson (TV)
        "D0:D0:03": "TCL", "04:B1:67": "TCL",
        # Hisense (TV)
        "00:2D:DF": "Hisense", "CC:A1:2B": "Hisense",
        # Roku
        "CC:6D:A0": "Roku",
        # Canon (imprimantes)
        "00:1E:8F": "Canon", "18:0C:AC": "Canon",
        # Epson (imprimantes)
        "00:26:AB": "Epson", "64:EB:8C": "Epson",
        # Brother (imprimantes)
        "00:1B:A9": "Brother", "00:80:77": "Brother",
        # Netatmo (IoT)
        "70:EE:50": "Netatmo",
        # Withings (IoT santé)
        "00:24:E4": "Withings",
        # Legrand / Netatmo
        "00:04:74": "Legrand",
    }

    def lookup(self, mac):
        # Cherche le fabricant à partir de l'adresse MAC
        if not mac:
            return ""

        # Normaliser le format MAC (AA:BB:CC:DD:EE:FF)
        mac_clean = mac.upper().replace("-", ":")
        prefix = mac_clean[:8]

        vendor = self.OUI_DATABASE.get(prefix, "")
        if not vendor and self.is_random_mac(mac_clean):
            return "(MAC aléatoire)"
        return vendor

    @staticmethod
    def is_random_mac(mac):
        # Détecte si une adresse MAC est aléatoire (locally-administered)
        # Le bit 1 du premier octet est à 1 pour les MAC locales/aléatoires
        # Les iPhones/Android modernes utilisent cette technique
        try:
            first_byte = int(mac.replace(":", "").replace("-", "")[:2], 16)
            return bool(first_byte & 0x02)
        except (ValueError, IndexError):
            return False

    def guess_device_type(self, vendor, open_ports=None, os_guess="", hostname=""):
        # Devine le type d'appareil à partir du fabricant, ports, OS et hostname
        vendor_lower = (vendor or "").lower()
        open_ports = open_ports or []
        hostname_lower = (hostname or "").lower()

        # Routeurs / Box opérateur
        if any(kw in vendor_lower for kw in ["freebox", "livebox", "sagemcom", "sfr",
                                               "bbox", "sercomm", "zte", "netgear",
                                               "tp-link", "huawei"]):
            if 80 in open_ports or 443 in open_ports:
                return "Routeur"

        # TV / Décodeurs
        if any(kw in vendor_lower for kw in ["vestel", "tcl", "hisense", "roku"]):
            return "TV connectée"

        # Imprimantes
        if any(kw in vendor_lower for kw in ["canon", "epson", "brother"]):
            return "Imprimante"

        # IoT
        if any(kw in vendor_lower for kw in ["espressif", "raspberry", "philips lighting",
                                               "sonos", "xiaomi", "tuya", "shenzhen",
                                               "netatmo", "withings", "legrand"]):
            return "IoT"

        # Apple — vendor connu ou détecté via mDNS/ports
        if "apple" in vendor_lower:
            if 62078 in open_ports or "iphone" in vendor_lower or "ipad" in vendor_lower:
                return "iPhone/iPad"
            return "Apple (Mac/iPhone)"

        # iPhone/iPad détecté via port Apple lockdown (62078) sans vendor
        if 62078 in open_ports:
            return "iPhone/iPad"

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

        # Détection par hostname
        if hostname_lower:
            if any(kw in hostname_lower for kw in ["iphone", "ipad"]):
                return "iPhone/iPad"
            if any(kw in hostname_lower for kw in ["macbook", "imac", "mac-"]):
                return "Mac"
            if any(kw in hostname_lower for kw in ["galaxy", "samsung", "sm-"]):
                return "Smartphone Samsung"
            if any(kw in hostname_lower for kw in ["huawei", "honor", "p30", "p40", "mate"]):
                return "Smartphone Huawei"
            if any(kw in hostname_lower for kw in ["pixel", "oneplus", "xiaomi", "redmi", "oppo"]):
                return "Smartphone Android"
            if any(kw in hostname_lower for kw in ["desktop", "laptop", "pc-", "workstation"]):
                return "PC"
            if any(kw in hostname_lower for kw in ["android", "phone"]):
                return "Smartphone"

        # Détection par MAC aléatoire + OS
        if "aléatoire" in vendor_lower or "aleatoire" in vendor_lower:
            os_lower = (os_guess or "").lower()
            if "ios" in os_lower:
                return "iPhone/iPad"
            if "linux" in os_lower or "android" in os_lower:
                return "Smartphone Android"
            if "windows" in os_lower:
                return "PC Windows (MAC privée)"
            return "Smartphone (MAC privée)"

        # Détection par OS si rien d'autre
        if os_guess:
            os_lower = os_guess.lower()
            if "windows" in os_lower:
                return "PC Windows"
            if "linux" in os_lower:
                return "Linux"

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

        # Estimation OS basée sur le TTL
        if host.ttl > 0:
            host.os_guess = self._guess_os_from_ttl(host.ttl)

        # Sonder le port 62078 (Apple lockdown) pour identifier les iPhones/iPads
        if not host.vendor or "aléatoire" in (host.vendor or ""):
            # Test port 62078 (Apple lockdown) — parfois fermé quand écran verrouillé
            is_apple = self._quick_probe_port(host.ip, 62078)
            # Test port 49152 (Apple service) — souvent ouvert sur iPhone
            if not is_apple:
                is_apple = self._quick_probe_port(host.ip, 49152)

            if is_apple:
                host.vendor = "Apple (iPhone/iPad)"
                host.device_type = "iPhone/iPad"
                self._resolve_device_name(host)
                host.os_guess = "iOS"
                return

            # Sonder le port 5353 (mDNS/Bonjour) pour les appareils Apple
            self._probe_mdns(host)

        # Tenter de résoudre le nom si hostname vide
        if not host.hostname:
            self._resolve_device_name(host)

        # Détection gateway
        if gateway_ip and host.ip == gateway_ip:
            host.is_gateway = True
            host.device_type = "Routeur/Gateway"
        else:
            port_numbers = [p.number for p in host.open_ports] if host.open_ports else []
            host.device_type = self.oui.guess_device_type(
                host.vendor, port_numbers, host.os_guess, host.hostname
            )

    def _quick_probe_port(self, ip, port, timeout=0.3):
        # Teste rapidement si un port est ouvert
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def _resolve_device_name(self, host):
        # Tente plusieurs méthodes pour obtenir le nom de l'appareil

        # Méthode 1 : Requête mDNS PTR (Bonjour/Avahi)
        try:
            mdns_name = self._mdns_ptr_resolve(host.ip)
            if mdns_name:
                host.hostname = mdns_name
                return
        except Exception:
            pass

        # Méthode 2 : NetBIOS (Windows)
        try:
            netbios_name = self._netbios_resolve(host.ip)
            if netbios_name:
                host.hostname = netbios_name
                return
        except Exception:
            pass

        # Méthode 3 : Vérifier la table DHCP via la Freebox API (si applicable)
        # Pas toujours disponible, on garde comme fallback

    def _mdns_ptr_resolve(self, ip):
        # Envoie une requête mDNS PTR pour résoudre IP -> nom.local
        try:
            parts = ip.split(".")
            rev = ".".join(reversed(parts))
            qname = f"{rev}.in-addr.arpa"

            # Construire la requête DNS PTR
            query = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            for part in qname.split("."):
                query += bytes([len(part)]) + part.encode()
            query += b"\x00\x00\x0c\x00\x01"  # PTR IN

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1.5)
            sock.sendto(query, ("224.0.0.251", 5353))

            data, addr = sock.recvfrom(4096)
            sock.close()

            # Extraire le nom depuis la réponse DNS
            return self._extract_dns_name(data)
        except Exception:
            return None

    def _extract_dns_name(self, data):
        # Extrait un nom lisible depuis une réponse DNS
        if len(data) < 12:
            return None

        # Parcourir les réponses (après le header de 12 bytes)
        # Chercher des chaînes lisibles qui ressemblent à un nom d'appareil
        readable = []
        i = 12
        while i < len(data):
            length = data[i]
            if length == 0 or length >= 0xC0:
                i += 1
                if length >= 0xC0:
                    i += 1
                continue
            if i + 1 + length <= len(data):
                try:
                    part = data[i + 1:i + 1 + length].decode("utf-8")
                    if part not in ("local", "in-addr", "arpa", "_tcp", "_udp") and len(part) > 1:
                        if not part.replace(".", "").isdigit():
                            readable.append(part)
                except UnicodeDecodeError:
                    pass
            i += 1 + length

        # Retourner le premier nom significatif
        for name in readable:
            if len(name) > 2 and not name.startswith("_"):
                return name
        return None

    def _netbios_resolve(self, ip):
        # Résout le nom NetBIOS d'un hôte Windows
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)

            # NetBIOS NBSTAT query (wildcard)
            query = b"\x80\x94\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20"
            # Encoder "*" (wildcard) en NetBIOS
            name = b"*" + b"\x00" * 15
            encoded = b""
            for c in name:
                encoded += bytes([((c >> 4) & 0x0F) + 0x41])
                encoded += bytes([(c & 0x0F) + 0x41])
            query += encoded
            query += b"\x00\x00\x21\x00\x01"

            sock.sendto(query, (ip, 137))
            data, _ = sock.recvfrom(4096)
            sock.close()

            if len(data) > 57:
                num_names = data[56]
                if num_names > 0 and len(data) >= 57 + 18:
                    name = data[57:57 + 15].decode("ascii", errors="replace").strip()
                    if name and name != "*":
                        return name
        except Exception:
            pass
        return None

    def _probe_mdns(self, host):
        # Tente une requête mDNS pour identifier l'appareil
        # Les appareils Apple répondent au mDNS même avec MAC aléatoire
        try:
            # Requête DNS inversée sur le lien local (.local)
            if not host.hostname:
                # Essayer la résolution mDNS via socket
                try:
                    name = socket.getfqdn(host.ip)
                    if name and name != host.ip and "." in name:
                        host.hostname = name
                except Exception:
                    pass

            # Identifier via le hostname mDNS
            if host.hostname:
                hn = host.hostname.lower()
                if "iphone" in hn or "ipad" in hn:
                    if not host.vendor or "aléatoire" in host.vendor:
                        host.vendor = "Apple (iPhone/iPad)"
                elif "macbook" in hn or "imac" in hn or "mac" in hn:
                    if not host.vendor or "aléatoire" in host.vendor:
                        host.vendor = "Apple (Mac)"
                elif "galaxy" in hn or "samsung" in hn:
                    if not host.vendor or "aléatoire" in host.vendor:
                        host.vendor = "Samsung"
                elif "android" in hn or "pixel" in hn:
                    if not host.vendor or "aléatoire" in host.vendor:
                        host.vendor = "Android"
        except Exception:
            pass

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
