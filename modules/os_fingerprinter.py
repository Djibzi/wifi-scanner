# os_fingerprinter.py — Détection du système d'exploitation
# Combine TTL, ports ouverts, bannières et OUI MAC pour deviner l'OS

import re

from core.models import Host
from core.config import ScannerConfig


class OSFingerprinter:
    # Estime le système d'exploitation de chaque hôte

    # Signatures de ports caractéristiques
    OS_PORT_SIGNATURES = {
        "Windows": {
            "required_any": [135, 139, 445, 3389],
            "weight": 3,
        },
        "Linux": {
            "required_any": [22],
            "bonus": [80, 443, 8080],
            "weight": 2,
        },
        "macOS": {
            "required_any": [22, 5353],
            "bonus": [548, 88],  # AFP, Kerberos
            "weight": 2,
        },
        "iOS": {
            "required_any": [62078],  # iphone-sync
            "weight": 4,
        },
        "Android (debug)": {
            "required_any": [5555],  # ADB
            "weight": 4,
        },
        "Imprimante": {
            "required_any": [9100, 631],
            "bonus": [515],  # LPR
            "weight": 4,
        },
    }

    # Patterns de bannières → OS
    BANNER_OS_PATTERNS = [
        (r"Ubuntu", "Ubuntu Linux"),
        (r"Debian", "Debian Linux"),
        (r"CentOS|Red Hat|RHEL", "CentOS/RHEL Linux"),
        (r"Fedora", "Fedora Linux"),
        (r"Arch", "Arch Linux"),
        (r"Raspbian|raspberry", "Raspberry Pi OS"),
        (r"Microsoft-IIS", "Windows Server"),
        (r"Microsoft-HTTPAPI", "Windows"),
        (r"Windows", "Windows"),
        (r"Darwin|macOS", "macOS"),
        (r"FreeBSD", "FreeBSD"),
        (r"OpenWrt", "OpenWrt"),
        (r"DD-WRT", "DD-WRT"),
        (r"lighttpd", "Linux (IoT/embarqué)"),
        (r"mini_httpd|micro_httpd", "Linux (IoT/embarqué)"),
        (r"Boa/", "Linux (IoT/embarqué)"),
    ]

    # MAC vendor → OS probable
    VENDOR_OS_MAP = {
        "Apple": "macOS/iOS",
        "Samsung": "Android/Tizen",
        "Xiaomi": "Android",
        "Huawei": "Android/HarmonyOS",
        "Google": "Android/ChromeOS",
        "Amazon": "Fire OS",
        "Raspberry Pi": "Raspberry Pi OS (Linux)",
        "Espressif": "FreeRTOS/Linux (IoT)",
        "Philips Lighting": "Firmware IoT",
        "Sonos": "Firmware Sonos",
        "Intel": "Windows/Linux",
        "Dell": "Windows/Linux",
        "HP": "Windows/Linux",
        "Microsoft": "Windows",
        "Synology": "DSM (Linux)",
        "QNAP": "QTS (Linux)",
    }

    def __init__(self, config=None, logger=None):
        self.config = config or ScannerConfig()
        self.logger = logger

    def fingerprint_hosts(self, hosts):
        # Effectue le fingerprinting OS sur tous les hôtes
        for host in hosts:
            self._fingerprint_host(host)
        return hosts

    def fingerprint_single(self, host):
        # Fingerprint un seul hôte
        self._fingerprint_host(host)
        return host

    def _fingerprint_host(self, host):
        # Combine tous les indices pour estimer l'OS
        scores = {}

        # Indice 1 : TTL
        ttl_guess = self._guess_from_ttl(host.ttl)
        if ttl_guess:
            scores[ttl_guess] = scores.get(ttl_guess, 0) + 2

        # Indice 2 : Ports ouverts
        port_guesses = self._guess_from_ports(host)
        for os_name, weight in port_guesses.items():
            scores[os_name] = scores.get(os_name, 0) + weight

        # Indice 3 : Bannières de services
        banner_guess = self._guess_from_banners(host)
        if banner_guess:
            scores[banner_guess] = scores.get(banner_guess, 0) + 3

        # Indice 4 : Vendor MAC
        vendor_guess = self._guess_from_vendor(host.vendor)
        if vendor_guess:
            scores[vendor_guess] = scores.get(vendor_guess, 0) + 1

        # Indice 5 : Hostname
        hostname_guess = self._guess_from_hostname(host.hostname)
        if hostname_guess:
            scores[hostname_guess] = scores.get(hostname_guess, 0) + 2

        # Prendre l'OS avec le score le plus élevé
        if scores:
            best_os = max(scores, key=scores.get)
            host.os_guess = best_os

        if self.logger and host.os_guess:
            self.logger.info(f"{host.ip} — OS estimé : {host.os_guess}")

    def _guess_from_ttl(self, ttl):
        # Estime l'OS à partir du TTL initial
        if ttl == 0:
            return ""
        # Les TTL diminuent à chaque saut, on cherche le TTL initial
        if ttl <= 64:
            return "Linux/macOS"
        elif ttl <= 128:
            return "Windows"
        else:
            return "Routeur/Switch"

    def _guess_from_ports(self, host):
        # Estime l'OS à partir des ports ouverts
        scores = {}
        open_port_numbers = host.get_open_port_numbers()

        if not open_port_numbers:
            return scores

        for os_name, sig in self.OS_PORT_SIGNATURES.items():
            required = sig.get("required_any", [])
            bonus = sig.get("bonus", [])
            weight = sig.get("weight", 1)

            # Vérifier si au moins un port requis est ouvert
            if any(p in open_port_numbers for p in required):
                scores[os_name] = weight

                # Bonus si des ports additionnels sont présents
                bonus_count = sum(1 for p in bonus if p in open_port_numbers)
                scores[os_name] += bonus_count

        return scores

    def _guess_from_banners(self, host):
        # Estime l'OS à partir des bannières de services
        all_banners = ""
        for port in host.open_ports:
            if port.banner:
                all_banners += " " + port.banner
            if port.version:
                all_banners += " " + port.version

        if not all_banners:
            return ""

        for pattern, os_name in self.BANNER_OS_PATTERNS:
            if re.search(pattern, all_banners, re.IGNORECASE):
                return os_name

        return ""

    def _guess_from_vendor(self, vendor):
        # Estime l'OS à partir du fabricant MAC
        if not vendor:
            return ""
        return self.VENDOR_OS_MAP.get(vendor, "")

    def _guess_from_hostname(self, hostname):
        # Estime l'OS à partir du nom d'hôte
        if not hostname:
            return ""

        hostname_lower = hostname.lower()

        if "macbook" in hostname_lower or "imac" in hostname_lower or "mac-" in hostname_lower:
            return "macOS"
        if "iphone" in hostname_lower or "ipad" in hostname_lower:
            return "iOS"
        if "desktop-" in hostname_lower or "laptop-" in hostname_lower or "pc-" in hostname_lower:
            return "Windows"
        if "android" in hostname_lower:
            return "Android"
        if "raspberrypi" in hostname_lower or "rpi" in hostname_lower:
            return "Raspberry Pi OS"
        if hostname_lower.endswith(".local"):
            # mDNS — pourrait être macOS, Linux, ou IoT
            return ""

        return ""
