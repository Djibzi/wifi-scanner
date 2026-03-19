# models.py — Classes de données du scanner réseau WiFi

from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum
from datetime import datetime


# --- Énumérations ---

class Severity(Enum):
    # Niveaux de sévérité des vulnérabilités
    CRITICAL = "CRITIQUE"
    HIGH = "HAUTE"
    MEDIUM = "MOYENNE"
    LOW = "FAIBLE"
    INFO = "INFO"


class ScanMode(Enum):
    # Modes de scan disponibles
    QUICK = "quick"
    FULL = "full"
    EXHAUSTIVE = "exhaustive"


class PortState(Enum):
    # États possibles d'un port
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class Protocol(Enum):
    # Protocoles réseau
    TCP = "TCP"
    UDP = "UDP"


# --- Classes de données réseau ---

@dataclass
class Port:
    # Représente un port scanné sur un hôte
    number: int
    protocol: Protocol = Protocol.TCP
    state: PortState = PortState.CLOSED
    service: str = ""            # Nom du service (SSH, HTTP, etc.)
    version: str = ""            # Version du service détectée
    banner: str = ""             # Bannière brute récupérée


@dataclass
class Vulnerability:
    # Représente une vulnérabilité détectée
    name: str
    severity: Severity
    description: str
    remediation: str
    host_ip: str = ""            # IP de l'hôte concerné
    port: int = 0                # Port concerné (0 si vulnérabilité réseau)
    cve: str = ""                # Identifiant CVE si applicable
    proof: str = ""              # Preuve de la vulnérabilité (bannière, réponse, etc.)


@dataclass
class Host:
    # Représente un appareil découvert sur le réseau
    ip: str
    mac: str = ""
    vendor: str = ""             # Fabricant déduit de l'adresse MAC (OUI lookup)
    hostname: str = ""           # Nom de la machine (DNS inverse, mDNS, NetBIOS)
    os_guess: str = ""           # Estimation du système d'exploitation
    device_type: str = ""        # Type d'appareil (routeur, PC, téléphone, IoT, imprimante)
    open_ports: List[Port] = field(default_factory=list)
    services: dict = field(default_factory=dict)         # {port: "service version"}
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    is_gateway: bool = False
    ttl: int = 0                 # TTL observé (utile pour le fingerprint OS)

    def get_open_port_numbers(self):
        # Retourne la liste des numéros de ports ouverts
        return [p.number for p in self.open_ports if p.state == PortState.OPEN]

    def get_vuln_count_by_severity(self):
        # Compte les vulnérabilités par niveau de sévérité
        counts = {s: 0 for s in Severity}
        for vuln in self.vulnerabilities:
            counts[vuln.severity] += 1
        return counts

    def has_critical_vulns(self):
        # Vérifie si l'hôte a des vulnérabilités critiques
        return any(v.severity == Severity.CRITICAL for v in self.vulnerabilities)


# --- Classes WiFi ---

@dataclass
class WifiVulnerability:
    # Vulnérabilité spécifique au réseau WiFi
    name: str
    severity: Severity
    description: str
    remediation: str


@dataclass
class WifiInfo:
    # Informations sur le réseau WiFi analysé
    ssid: str = ""
    bssid: str = ""
    security: str = ""           # Open, WEP, WPA, WPA2, WPA3
    encryption: str = ""         # TKIP, CCMP/AES
    channel: int = 0
    frequency: str = ""          # 2.4 GHz ou 5 GHz
    signal_strength: int = 0     # en dBm
    gateway_ip: str = ""
    subnet_mask: str = ""
    dns_servers: List[str] = field(default_factory=list)
    wps_enabled: Optional[bool] = None
    pmf_enabled: Optional[bool] = None    # Protected Management Frames
    vulnerabilities: List[WifiVulnerability] = field(default_factory=list)

    def get_security_level(self):
        # Retourne un score de sécurité du WiFi (0-10)
        scores = {"WPA3": 10, "WPA2": 7, "WPA": 4, "WEP": 1, "Open": 0}
        return scores.get(self.security, 0)


# --- Résultat global ---

@dataclass
class ScanResult:
    # Résultat complet d'un scan
    wifi_info: Optional[WifiInfo] = None
    hosts: List[Host] = field(default_factory=list)
    scan_start: str = field(default_factory=lambda: datetime.now().isoformat())
    scan_end: str = ""
    scan_mode: str = "quick"
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

    def get_total_vulns(self):
        # Nombre total de vulnérabilités (WiFi + hôtes)
        total = len(self.vulnerabilities)
        if self.wifi_info:
            total += len(self.wifi_info.vulnerabilities)
        for host in self.hosts:
            total += len(host.vulnerabilities)
        return total

    def get_vulns_by_severity(self):
        # Agrège toutes les vulnérabilités par sévérité
        all_vulns = list(self.vulnerabilities)
        if self.wifi_info:
            # Convertir WifiVulnerability en Vulnerability pour le comptage
            for wv in self.wifi_info.vulnerabilities:
                all_vulns.append(Vulnerability(
                    name=wv.name,
                    severity=wv.severity,
                    description=wv.description,
                    remediation=wv.remediation,
                ))
        for host in self.hosts:
            all_vulns.extend(host.vulnerabilities)

        result = {s: [] for s in Severity}
        for vuln in all_vulns:
            result[vuln.severity].append(vuln)
        return result

    def get_security_score(self):
        # Calcule le score de sécurité global (0-100)
        score = 100

        # Déductions par vulnérabilité
        deductions = {
            Severity.CRITICAL: 20,
            Severity.HIGH: 10,
            Severity.MEDIUM: 5,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }

        vulns_by_severity = self.get_vulns_by_severity()
        for severity, vulns in vulns_by_severity.items():
            score -= len(vulns) * deductions[severity]

        # Bonus
        if self.wifi_info:
            if self.wifi_info.security == "WPA3":
                score += 5
            if self.wifi_info.wps_enabled is False:
                score += 3

        # Plafonner entre 0 et 100
        return max(0, min(100, score))

    def get_grade(self):
        # Retourne la note (A à F) basée sur le score
        score = self.get_security_score()
        if score >= 90:
            return "A"
        elif score >= 75:
            return "B"
        elif score >= 60:
            return "C"
        elif score >= 40:
            return "D"
        return "F"

    def finalize(self):
        # Marque la fin du scan
        self.scan_end = datetime.now().isoformat()
