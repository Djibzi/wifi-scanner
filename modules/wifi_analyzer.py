# wifi_analyzer.py — Analyse la sécurité du réseau WiFi
# Récupère les infos du WiFi connecté et détecte les vulnérabilités

import subprocess
import re
import platform
import socket
import struct

from core.models import WifiInfo, WifiVulnerability, Severity
from core.config import ScannerConfig


class WifiAnalyzer:
    # Analyse le réseau WiFi actuel et détecte les vulnérabilités

    def __init__(self, config=None, logger=None):
        self.config = config or ScannerConfig()
        self.logger = logger
        self.os_type = platform.system()

    def analyze(self):
        # Lance l'analyse complète du WiFi
        info = WifiInfo()

        if self.os_type == "Windows":
            self._get_info_windows(info)
        else:
            self._get_info_linux(info)

        # Détection des vulnérabilités
        self._check_encryption_vulns(info)
        self._check_wps(info)
        self._check_dns(info)
        self._check_channel(info)

        if self.logger:
            self.logger.info(f"WiFi analysé : SSID={info.ssid}, Sécurité={info.security}")
            for vuln in info.vulnerabilities:
                self.logger.vuln(vuln.severity.value, vuln.name)

        return info

    # --- Récupération des infos Windows ---

    def _get_info_windows(self, info):
        # Récupère les infos WiFi via netsh et ipconfig sur Windows
        self._parse_netsh_interfaces(info)
        self._parse_ipconfig(info)

    def _parse_netsh_interfaces(self, info):
        # Parse la sortie de netsh wlan show interfaces
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True, text=True, timeout=10, encoding="cp850"
            )
            output = result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            if self.logger:
                self.logger.error("Impossible d'exécuter netsh wlan show interfaces")
            return

        # SSID
        match = re.search(r"^\s*SSID\s*:\s*(.+)$", output, re.MULTILINE)
        if match:
            info.ssid = match.group(1).strip()

        # BSSID
        match = re.search(r"BSSID\s*:\s*([\da-fA-F:]+)", output)
        if match:
            info.bssid = match.group(1).strip()

        # Type de réseau / Authentification
        match = re.search(r"Authentification\s*:\s*(.+)", output)
        if not match:
            match = re.search(r"Authentication\s*:\s*(.+)", output)
        if match:
            auth = match.group(1).strip()
            info.security = self._parse_security_type(auth)

        # Chiffrement
        match = re.search(r"Chiffrement\s*:\s*(.+)", output)
        if not match:
            match = re.search(r"Cipher\s*:\s*(.+)", output)
        if match:
            cipher = match.group(1).strip()
            info.encryption = self._parse_encryption_type(cipher)

        # Canal
        match = re.search(r"Canal\s*:\s*(\d+)", output)
        if not match:
            match = re.search(r"Channel\s*:\s*(\d+)", output)
        if match:
            info.channel = int(match.group(1))
            # Déduire la fréquence du canal
            info.frequency = "5 GHz" if info.channel > 14 else "2.4 GHz"

        # Signal
        match = re.search(r"Signal\s*:\s*(\d+)%", output)
        if match:
            # Convertir le pourcentage en dBm approximatif
            percent = int(match.group(1))
            info.signal_strength = self._percent_to_dbm(percent)

    def _parse_ipconfig(self, info):
        # Parse ipconfig /all pour gateway, DNS et masque
        try:
            result = subprocess.run(
                ["ipconfig", "/all"],
                capture_output=True, text=True, timeout=10, encoding="cp850"
            )
            output = result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            if self.logger:
                self.logger.error("Impossible d'exécuter ipconfig /all")
            return

        # Trouver la section de l'adaptateur WiFi
        # Prioriser "Wi-Fi" dans la première ligne, sinon "sans fil" connecté
        sections = re.split(r"\r?\n(?=\S)", output)
        wifi_section = ""
        fallback_section = ""
        for section in sections:
            first_line = section.strip().split("\n")[0].lower()
            # Priorité 1 : section nommée explicitement "Wi-Fi"
            if "wi-fi" in first_line:
                wifi_section = section
                break
            # Priorité 2 : section "sans fil" qui n'est pas déconnectée
            if "sans fil" in first_line and "d\xe9connect\xe9" not in section.lower() and not fallback_section:
                fallback_section = section

        if not wifi_section:
            wifi_section = fallback_section or output

        # Passerelle (IPv4 uniquement — peut être sur la ligne suivante)
        lines = wifi_section.split("\n")
        gw_found = False
        for i, line in enumerate(lines):
            if "passerelle" in line.lower() or "gateway" in line.lower():
                gw_found = True
                # Chercher une IPv4 sur cette ligne
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    info.gateway_ip = match.group(1)
                    break
            # Si on a trouvé la ligne passerelle mais l'IPv4 est sur la ligne suivante
            if gw_found and not info.gateway_ip:
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    info.gateway_ip = match.group(1)
                    break

        # Masque de sous-réseau
        match = re.search(r"(?:Masque|Mask)[^\n]*?(\d+\.\d+\.\d+\.\d+)", wifi_section)
        if match:
            info.subnet_mask = match.group(1).strip()

        # Serveurs DNS — chercher les IPs sur les lignes contenant "DNS" (hors suffixe)
        dns_ips = []
        in_dns_block = False
        for line in lines:
            line_lower = line.lower()
            if "serveurs dns" in line_lower or "dns servers" in line_lower:
                in_dns_block = True
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    dns_ips.append(match.group(1))
            elif in_dns_block:
                # Lignes indentées après "Serveurs DNS" = DNS supplémentaires
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    dns_ips.append(match.group(1))
                else:
                    in_dns_block = False
        if dns_ips:
            info.dns_servers = list(set(dns_ips))

    # --- Récupération des infos Linux ---

    def _get_info_linux(self, info):
        # Récupère les infos WiFi via nmcli et ip sur Linux
        self._parse_nmcli(info)
        if not info.ssid:
            self._parse_iwconfig(info)
        self._parse_ip_route(info)
        self._parse_resolv_conf(info)

    def _parse_nmcli(self, info):
        # Parse la sortie de nmcli pour récupérer les infos WiFi
        try:
            result = subprocess.run(
                ["nmcli", "-t", "-f",
                 "active,ssid,bssid,freq,signal,security",
                 "dev", "wifi"],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return

        for line in output.strip().split("\n"):
            parts = line.split(":")
            if len(parts) >= 6 and parts[0].lower() == "yes":
                # Réseau actif trouvé
                info.ssid = parts[1] if parts[1] != "--" else ""
                # BSSID peut contenir des ":" donc on reconstruit
                # Format: yes:SSID:AA:BB:CC:DD:EE:FF:freq:signal:security
                bssid_parts = parts[2:8]
                info.bssid = ":".join(bssid_parts) if len(bssid_parts) == 6 else parts[2]

                # Trouver la fréquence et le signal après le BSSID
                remaining = parts[8:]
                if len(remaining) >= 2:
                    freq = remaining[0].strip()
                    info.frequency = "5 GHz" if "5" in freq else "2.4 GHz"
                    try:
                        info.signal_strength = int(remaining[1])
                    except ValueError:
                        pass
                    if len(remaining) >= 3:
                        info.security = self._parse_security_type(remaining[2])
                break

    def _parse_iwconfig(self, info):
        # Parse iwconfig comme fallback
        try:
            result = subprocess.run(
                ["iwconfig"],
                capture_output=True, text=True, timeout=10,
                stderr=subprocess.DEVNULL
            )
            output = result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return

        # SSID
        match = re.search(r'ESSID:"([^"]*)"', output)
        if match:
            info.ssid = match.group(1)

        # Fréquence
        match = re.search(r"Frequency[=:](\d+\.?\d*)\s*GHz", output)
        if match:
            freq = float(match.group(1))
            info.frequency = "5 GHz" if freq > 3 else "2.4 GHz"

        # Signal
        match = re.search(r"Signal level[=:](-?\d+)\s*dBm", output)
        if match:
            info.signal_strength = int(match.group(1))

        # Canal
        match = re.search(r"Channel[=:](\d+)", output)
        if match:
            info.channel = int(match.group(1))

    def _parse_ip_route(self, info):
        # Récupère la gateway via ip route
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=10
            )
            match = re.search(r"default via ([\d.]+)", result.stdout)
            if match:
                info.gateway_ip = match.group(1)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Masque de sous-réseau via ip addr
        try:
            result = subprocess.run(
                ["ip", "-o", "addr", "show"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split("\n"):
                if info.gateway_ip and "wl" in line:
                    match = re.search(r"inet ([\d.]+)/(\d+)", line)
                    if match:
                        prefix = int(match.group(2))
                        info.subnet_mask = self._prefix_to_netmask(prefix)
                        break
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    def _parse_resolv_conf(self, info):
        # Récupère les DNS depuis /etc/resolv.conf
        try:
            with open("/etc/resolv.conf", "r") as f:
                content = f.read()
            info.dns_servers = re.findall(r"nameserver\s+([\d.]+)", content)
        except (FileNotFoundError, PermissionError):
            pass

    # --- Détection des vulnérabilités WiFi ---

    def _check_encryption_vulns(self, info):
        # Vérifie les failles liées au chiffrement WiFi
        if not info.security:
            return

        if info.security == "Open":
            info.vulnerabilities.append(WifiVulnerability(
                name="Réseau WiFi ouvert",
                severity=Severity.CRITICAL,
                description="Le réseau n'a aucun mot de passe. Tout appareil peut se connecter "
                           "et tout le trafic non-HTTPS est lisible en clair.",
                remediation="Configurer WPA3 (ou WPA2-AES minimum) sur le routeur avec un "
                           "mot de passe fort d'au moins 12 caractères."
            ))

        elif info.security == "WEP":
            info.vulnerabilities.append(WifiVulnerability(
                name="Chiffrement WEP (obsolète)",
                severity=Severity.CRITICAL,
                description="WEP est cassable en quelques minutes avec des outils comme aircrack-ng. "
                           "Il n'offre aucune protection réelle.",
                remediation="Migrer immédiatement vers WPA2-AES ou WPA3."
            ))

        elif info.security == "WPA" and info.encryption == "TKIP":
            info.vulnerabilities.append(WifiVulnerability(
                name="WPA avec TKIP",
                severity=Severity.HIGH,
                description="TKIP a des faiblesses cryptographiques connues (attaque Beck-Tews). "
                           "Il est déprécié depuis 2012.",
                remediation="Passer en WPA2 avec AES/CCMP."
            ))

        elif info.security == "WPA2" and info.encryption == "TKIP":
            info.vulnerabilities.append(WifiVulnerability(
                name="WPA2 avec TKIP au lieu de AES",
                severity=Severity.MEDIUM,
                description="WPA2 devrait utiliser AES/CCMP. TKIP est conservé uniquement pour la "
                           "compatibilité avec d'anciens appareils.",
                remediation="Configurer WPA2 en mode AES/CCMP uniquement."
            ))

        # Vérifier PMF
        if info.security == "WPA2" and not info.pmf_enabled:
            info.vulnerabilities.append(WifiVulnerability(
                name="WPA2 sans PMF (802.11w)",
                severity=Severity.MEDIUM,
                description="Sans PMF, le réseau est vulnérable aux attaques de déauthentification. "
                           "Un attaquant peut déconnecter n'importe quel appareil.",
                remediation="Activer PMF (802.11w) dans les paramètres avancés du routeur."
            ))

    def _check_wps(self, info):
        # Vérifie si WPS est activé
        if self.os_type == "Windows":
            self._detect_wps_windows(info)

        if info.wps_enabled:
            info.vulnerabilities.append(WifiVulnerability(
                name="WPS activé",
                severity=Severity.HIGH,
                description="Le PIN WPS à 8 chiffres peut être brute-forcé en quelques heures "
                           "(attaque Reaver). Le mot de passe WiFi est alors révélé.",
                remediation="Désactiver WPS dans les paramètres du routeur."
            ))

    def _detect_wps_windows(self, info):
        # Tente de détecter WPS via netsh wlan show networks
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True, text=True, timeout=10, encoding="cp850"
            )
            output = result.stdout

            # Chercher le réseau actuel et vérifier WPS
            # netsh ne donne pas directement WPS, on laisse None (inconnu)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    def _check_dns(self, info):
        # Vérifie la configuration DNS
        for dns in info.dns_servers:
            # Le DNS du routeur est normal
            if dns == info.gateway_ip:
                continue
            # Vérifier si c'est un DNS de confiance
            if (dns not in self.config.TRUSTED_DNS
                    and not dns.startswith("192.168.")
                    and not dns.startswith("10.")
                    and not dns.startswith("172.")):
                info.vulnerabilities.append(WifiVulnerability(
                    name=f"Serveur DNS inhabituel : {dns}",
                    severity=Severity.MEDIUM,
                    description=f"Le serveur DNS {dns} n'est pas un DNS public reconnu. "
                               "Cela peut indiquer un détournement DNS (DNS hijacking).",
                    remediation="Vérifier la configuration DNS du routeur. Utiliser un DNS "
                               "de confiance (1.1.1.1, 8.8.8.8, 9.9.9.9)."
                ))

    def _check_channel(self, info):
        # Vérifie la congestion du canal WiFi
        if info.channel == 0:
            return

        neighbor_count = self._count_neighbors_on_channel(info.channel)
        if neighbor_count > 3:
            info.vulnerabilities.append(WifiVulnerability(
                name=f"Canal {info.channel} surchargé ({neighbor_count} réseaux)",
                severity=Severity.LOW,
                description=f"Le canal {info.channel} est utilisé par {neighbor_count} autres réseaux. "
                           "Cela peut dégrader les performances.",
                remediation="Changer de canal dans les paramètres du routeur. "
                           "En 2.4 GHz, préférer les canaux 1, 6 ou 11 (non-chevauchants)."
            ))

    def _count_neighbors_on_channel(self, channel):
        # Compte les réseaux voisins sur le même canal
        count = 0
        try:
            if self.os_type == "Windows":
                result = subprocess.run(
                    ["netsh", "wlan", "show", "networks", "mode=bssid"],
                    capture_output=True, text=True, timeout=10, encoding="cp850"
                )
                # Compter les occurrences du canal
                matches = re.findall(r"Canal\s*:\s*(\d+)", result.stdout)
                if not matches:
                    matches = re.findall(r"Channel\s*:\s*(\d+)", result.stdout)
                count = sum(1 for ch in matches if int(ch) == channel) - 1  # -1 pour notre réseau
            else:
                result = subprocess.run(
                    ["nmcli", "-t", "-f", "chan", "dev", "wifi", "list"],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.strip().split("\n"):
                    if line.strip() == str(channel):
                        count += 1
                count -= 1  # -1 pour notre réseau
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return max(0, count)

    # --- Utilitaires ---

    def _parse_security_type(self, raw):
        # Convertit la chaîne d'authentification en type de sécurité standard
        raw_lower = raw.lower()
        if "wpa3" in raw_lower:
            return "WPA3"
        elif "wpa2" in raw_lower:
            return "WPA2"
        elif "wpa" in raw_lower:
            return "WPA"
        elif "wep" in raw_lower:
            return "WEP"
        elif "open" in raw_lower or "ouvert" in raw_lower:
            return "Open"
        return raw

    def _parse_encryption_type(self, raw):
        # Convertit la chaîne de chiffrement en type standard
        raw_lower = raw.lower()
        if "ccmp" in raw_lower or "aes" in raw_lower:
            return "CCMP"
        elif "tkip" in raw_lower:
            return "TKIP"
        return raw

    def _percent_to_dbm(self, percent):
        # Convertit un pourcentage de signal en dBm approximatif
        # Formule approximative : dBm = (percent / 2) - 100
        return int((percent / 2) - 100)

    def _prefix_to_netmask(self, prefix):
        # Convertit un préfixe CIDR en masque de sous-réseau
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        return socket.inet_ntoa(struct.pack(">I", mask))
