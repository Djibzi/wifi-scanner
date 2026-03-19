# config.py — Configuration globale du scanner réseau WiFi

import os
import json


class ScannerConfig:
    # Configuration par défaut du scanner

    # Ports critiques à toujours scanner
    CRITICAL_PORTS = {
        # Administration à distance
        22: "SSH",
        23: "Telnet",
        3389: "RDP",
        5900: "VNC",
        5901: "VNC-1",
        # Web
        80: "HTTP",
        443: "HTTPS",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
        8888: "HTTP-Alt2",
        # Bases de données
        3306: "MySQL",
        5432: "PostgreSQL",
        1433: "MSSQL",
        27017: "MongoDB",
        6379: "Redis",
        # Fichiers et partages
        21: "FTP",
        445: "SMB",
        139: "NetBIOS-SSN",
        2049: "NFS",
        # Mail
        25: "SMTP",
        110: "POP3",
        143: "IMAP",
        # DNS
        53: "DNS",
        # IoT
        1883: "MQTT",
        8883: "MQTT-TLS",
        5683: "CoAP",
        # Divers
        161: "SNMP",
        162: "SNMP-Trap",
        389: "LDAP",
        636: "LDAPS",
        1900: "SSDP/UPnP",
        5353: "mDNS",
        9100: "Imprimante",
        # Proxy et VPN
        1080: "SOCKS",
        3128: "Squid Proxy",
        1194: "OpenVPN",
        1723: "PPTP VPN",
    }

    # DNS de confiance connus
    TRUSTED_DNS = [
        "1.1.1.1", "1.0.0.1",               # Cloudflare
        "8.8.8.8", "8.8.4.4",               # Google
        "9.9.9.9", "149.112.112.112",        # Quad9
        "208.67.222.222", "208.67.220.220",  # OpenDNS
    ]

    # Chemins des bases de données de vulnérabilités
    VULN_DB_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "vuln_db")
    REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")

    def __init__(self):
        # Paramètres de scan
        self.scan_mode = "quick"          # quick, full, exhaustive
        self.target = None                # IP spécifique ou None pour tout le réseau
        self.wifi_only = False            # Analyser uniquement le WiFi
        self.passive_mode = False         # Mode écoute passive uniquement
        self.test_credentials = False     # Tester les identifiants par défaut
        self.report_format = "html"       # html, md, json
        self.output_file = None           # Fichier de sortie du rapport

        # Paramètres réseau
        self.timeout = 0.5                # Timeout en secondes pour le réseau local
        self.max_threads = 200            # Nombre max de threads pour le scan de ports
        self.interface = None             # Interface réseau à utiliser

        # Paramètres de verbosité
        self.verbose = False
        self.debug = False

    def get_ports_to_scan(self):
        # Retourne la liste des ports selon le mode de scan
        if self.scan_mode == "quick":
            # Top ports critiques uniquement
            return list(self.CRITICAL_PORTS.keys())
        elif self.scan_mode == "full":
            # Top 1000 ports les plus courants
            return list(range(1, 1001))
        elif self.scan_mode == "exhaustive":
            # Tous les ports
            return list(range(1, 65536))
        return list(self.CRITICAL_PORTS.keys())

    def get_port_name(self, port):
        # Retourne le nom du service associé à un port
        return self.CRITICAL_PORTS.get(port, "unknown")

    def load_vuln_db(self, filename):
        # Charge un fichier JSON de la base de vulnérabilités
        filepath = os.path.join(self.VULN_DB_DIR, filename)
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    def set_scan_mode(self, mode):
        # Définit le mode de scan et ajuste les paramètres
        self.scan_mode = mode
        if mode == "quick":
            self.timeout = 0.5
            self.max_threads = 200
        elif mode == "full":
            self.timeout = 1.0
            self.max_threads = 300
        elif mode == "exhaustive":
            self.timeout = 2.0
            self.max_threads = 500

    def __repr__(self):
        return (
            f"ScannerConfig(mode={self.scan_mode}, target={self.target}, "
            f"threads={self.max_threads}, timeout={self.timeout})"
        )
