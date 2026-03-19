# vuln_detector.py — Détection de vulnérabilités
# Analyse chaque hôte et service pour détecter les failles connues

import re
import json
import os

from core.models import Host, Vulnerability, Severity
from core.config import ScannerConfig


class VulnDetector:
    # Détecte les vulnérabilités sur les hôtes scannés

    def __init__(self, config=None, logger=None):
        self.config = config or ScannerConfig()
        self.logger = logger

        # Charger les bases de données
        self.dangerous_ports = self.config.load_vuln_db("dangerous_ports.json")
        self.known_vulns = self.config.load_vuln_db("known_vulns.json")

    def detect_all(self, hosts, wifi_info=None):
        # Lance toutes les détections sur tous les hôtes
        all_vulns = []

        for host in hosts:
            # Vérifier les services dangereux exposés
            self._check_dangerous_services(host)

            # Vérifier les vulnérabilités par version de service
            self._check_version_vulns(host)

            # Vérifier le routeur spécifiquement
            if host.is_gateway:
                self._check_gateway_vulns(host)

            # Vérifier la segmentation réseau
            all_vulns.extend(host.vulnerabilities)

        if self.logger:
            total = sum(len(h.vulnerabilities) for h in hosts)
            self.logger.info(f"{total} vulnérabilité(s) détectée(s) au total")

        return all_vulns

    def detect_single(self, host):
        # Détecte les vulnérabilités sur un seul hôte
        self._check_dangerous_services(host)
        self._check_version_vulns(host)
        if host.is_gateway:
            self._check_gateway_vulns(host)
        return host.vulnerabilities

    # --- Services dangereux ---

    def _check_dangerous_services(self, host):
        # Vérifie si des services dangereux sont exposés
        for port in host.open_ports:
            port_str = str(port.number)
            if port_str in self.dangerous_ports:
                info = self.dangerous_ports[port_str]
                severity = self._parse_severity(info["severity"])

                # Vérifier si c'est vraiment dangereux selon le contexte
                if not self._is_false_positive(host, port):
                    vuln = Vulnerability(
                        name=f"Service exposé : {info['name']} (port {port.number})",
                        severity=severity,
                        description=info["description"],
                        remediation=info["remediation"],
                        host_ip=host.ip,
                        port=port.number,
                        proof=f"Port {port.number} ouvert — {port.banner[:100]}" if port.banner else f"Port {port.number} ouvert",
                    )
                    host.vulnerabilities.append(vuln)

                    if self.logger:
                        self.logger.vuln(severity.value, f"{host.ip}:{port.number} — {info['name']}")

    def _is_false_positive(self, host, port):
        # Réduit les faux positifs selon le contexte
        # SMB sur Windows est normal (usage interne)
        if port.number == 445 and "Windows" in (host.os_guess or ""):
            return False  # On garde quand même comme info

        # FTP avec FTPS (TLS) n'est pas dangereux
        if port.number == 21 and port.banner and "TLS" in port.banner:
            return True

        return False

    # --- Vulnérabilités par version ---

    def _check_version_vulns(self, host):
        # Compare les versions détectées avec la base de vulnérabilités connues
        for port in host.open_ports:
            if not port.version:
                continue

            # Identifier le logiciel et la version
            software, version = self._extract_software_version(port)
            if not software or not version:
                continue

            # Chercher dans la base de vulnérabilités
            if software in self.known_vulns:
                for version_range, cve_list in self.known_vulns[software].items():
                    if self._version_matches(version, version_range):
                        for cve_info in cve_list:
                            severity = self._parse_severity(cve_info["severity"])
                            vuln = Vulnerability(
                                name=f"{cve_info['cve']} — {software} {version}",
                                severity=severity,
                                description=cve_info["description"],
                                remediation=f"Mettre à jour {software} vers la dernière version stable.",
                                host_ip=host.ip,
                                port=port.number,
                                cve=cve_info["cve"],
                                proof=f"Version détectée : {software} {version}",
                            )
                            host.vulnerabilities.append(vuln)

                            if self.logger:
                                self.logger.vuln(severity.value,
                                    f"{host.ip}:{port.number} — {cve_info['cve']} ({software} {version})")

    def _extract_software_version(self, port):
        # Extrait le nom du logiciel et sa version depuis la bannière/version
        version_str = port.version or ""
        banner = port.banner or ""
        combined = f"{version_str} {banner}"

        # Patterns de détection logiciel/version
        patterns = [
            (r"OpenSSH[_/ ]([\d.]+)", "OpenSSH"),
            (r"Apache[/ ]([\d.]+)", "Apache"),
            (r"nginx[/ ]([\d.]+)", "nginx"),
            (r"ProFTPD ([\d.]+)", "ProFTPD"),
            (r"vsftpd ([\d.]+)", "vsftpd"),
            (r"Microsoft-IIS[/ ]([\d.]+)", "Microsoft-IIS"),
            (r"MySQL ([\d.]+)", "MySQL"),
            (r"MariaDB[- ]([\d.]+)", "MySQL"),
            (r"redis_version:([\d.]+)", "Redis"),
            (r"Redis[/ ]([\d.]+)", "Redis"),
            (r"Postfix", "Postfix"),
        ]

        for pattern, software in patterns:
            match = re.search(pattern, combined, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex else ""
                return software, version

        return "", ""

    def _version_matches(self, actual_version, version_range):
        # Vérifie si une version est dans la plage vulnérable
        # Format du range : "< X.Y.Z"
        match = re.match(r"<\s*([\d.]+)", version_range)
        if not match:
            return False

        target = match.group(1)
        try:
            actual_parts = [int(x) for x in actual_version.split(".")]
            target_parts = [int(x) for x in target.split(".")]

            # Padding pour comparer des longueurs égales
            max_len = max(len(actual_parts), len(target_parts))
            actual_parts.extend([0] * (max_len - len(actual_parts)))
            target_parts.extend([0] * (max_len - len(target_parts)))

            return actual_parts < target_parts
        except (ValueError, IndexError):
            return False

    # --- Vulnérabilités du routeur ---

    def _check_gateway_vulns(self, host):
        # Vérifications spécifiques au routeur/gateway

        # Vérifier si le panneau d'admin est en HTTP (pas HTTPS)
        http_admin = False
        https_admin = False
        for port in host.open_ports:
            if port.number == 80 and port.banner and "admin" in port.banner.lower():
                http_admin = True
            if port.number == 443:
                https_admin = True

        if http_admin and not https_admin:
            host.vulnerabilities.append(Vulnerability(
                name="Panneau d'admin du routeur en HTTP",
                severity=Severity.HIGH,
                description="Le panneau d'administration du routeur est accessible en HTTP "
                           "(non chiffré). Les identifiants de connexion sont transmis en clair.",
                remediation="Activer HTTPS sur le panneau d'admin du routeur. "
                           "Accéder à l'interface via https:// uniquement.",
                host_ip=host.ip,
                port=80,
            ))

        # Vérifier UPnP
        for port in host.open_ports:
            if port.number == 1900:
                host.vulnerabilities.append(Vulnerability(
                    name="UPnP activé sur le routeur",
                    severity=Severity.MEDIUM,
                    description="UPnP permet à n'importe quel appareil du réseau local d'ouvrir "
                               "des ports sur le routeur sans authentification.",
                    remediation="Désactiver UPnP dans les paramètres du routeur.",
                    host_ip=host.ip,
                    port=1900,
                ))
                break

    # --- Utilitaires ---

    def _parse_severity(self, severity_str):
        # Convertit une chaîne de sévérité en enum Severity
        mapping = {
            "CRITIQUE": Severity.CRITICAL,
            "HAUTE": Severity.HIGH,
            "MOYENNE": Severity.MEDIUM,
            "FAIBLE": Severity.LOW,
            "INFO": Severity.INFO,
        }
        return mapping.get(severity_str, Severity.MEDIUM)
