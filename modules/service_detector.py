# service_detector.py — Identification des services et versions
# Banner grabbing TCP + identification HTTP avancée

import socket
import ssl
import re

from core.models import Host, Port
from core.config import ScannerConfig


class ServiceDetector:
    # Identifie les services et versions sur les ports ouverts

    # Probes d'identification : données à envoyer pour provoquer une réponse
    SERVICE_PROBES = {
        "http": b"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: WifiScanner/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        "https": b"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: WifiScanner/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        "smtp": None,  # SMTP envoie sa bannière automatiquement
        "ftp": None,   # FTP aussi
        "ssh": None,   # SSH aussi
        "pop3": None,
        "imap": None,
        "mysql": None,
        "redis": b"INFO\r\n",
        "mongodb": b"\x41\x00\x00\x00\x3a\x30\x00\x00\xff\xff\xff\xff\xd4\x07\x00\x00\x00\x00\x00\x00test.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x1b\x00\x00\x00\x01ismaster\x00\x00\x00\x00\x00\x00\xf0\x3f\x00",
    }

    # Ports associés à des protocoles connus
    PORT_PROTOCOLS = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        80: "http", 110: "pop3", 143: "imap", 443: "https",
        3306: "mysql", 5432: "postgresql", 6379: "redis",
        27017: "mongodb", 8080: "http", 8443: "https",
        8888: "http", 3389: "rdp", 5900: "vnc",
        1883: "mqtt", 9100: "printer",
    }

    def __init__(self, config=None, logger=None):
        self.config = config or ScannerConfig()
        self.logger = logger

    def detect_services(self, hosts):
        # Identifie les services sur tous les hôtes
        for host in hosts:
            self._detect_host_services(host)
        return hosts

    def detect_single_host(self, host):
        # Identifie les services sur un seul hôte
        self._detect_host_services(host)
        return host

    def _detect_host_services(self, host):
        # Identifie les services sur chaque port ouvert d'un hôte
        if not host.open_ports:
            return

        if self.logger:
            self.logger.info(f"Détection des services sur {host.ip}...")

        for port in host.open_ports:
            self._identify_service(host.ip, port)
            if port.version:
                host.services[port.number] = f"{port.service} {port.version}"
                if self.logger:
                    self.logger.port_found(host.ip, port.number, f"{port.service} {port.version}")

    def _identify_service(self, ip, port):
        # Identifie le service sur un port en récupérant la bannière
        protocol = self.PORT_PROTOCOLS.get(port.number, "")

        # Ports HTTPS — utiliser TLS
        if port.number in (443, 8443) or protocol == "https":
            self._grab_https_banner(ip, port)
            return

        # Ports HTTP — envoyer une requête GET
        if protocol == "http":
            self._grab_http_banner(ip, port)
            return

        # Autres services — banner grabbing générique
        self._grab_banner(ip, port, protocol)

    def _grab_banner(self, ip, port, protocol=""):
        # Banner grabbing TCP générique
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.config.timeout * 4)
        try:
            sock.connect((ip, port.number))

            # Certains services envoient leur bannière dès la connexion
            # D'autres nécessitent un probe
            probe = self.SERVICE_PROBES.get(protocol)
            if probe:
                if isinstance(probe, bytes) and b"{host}" in probe:
                    probe = probe.replace(b"{host}", ip.encode())
                sock.send(probe)

            # Lire la réponse
            data = sock.recv(4096)
            if data:
                banner = data.decode("utf-8", errors="replace").strip()
                port.banner = banner[:500]
                self._parse_banner(port, banner)

        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        finally:
            sock.close()

    def _grab_http_banner(self, ip, port):
        # Récupère les headers HTTP et identifie le serveur
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.config.timeout * 4)
        try:
            sock.connect((ip, port.number))
            request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: WifiScanner/1.0\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())

            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 8192:
                        break
                except socket.timeout:
                    break

            if response:
                text = response.decode("utf-8", errors="replace")
                port.banner = text[:500]
                port.service = "HTTP"
                self._parse_http_response(port, text)

        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        finally:
            sock.close()

    def _grab_https_banner(self, ip, port):
        # Récupère les headers HTTPS et les infos du certificat TLS
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.config.timeout * 4)
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                ssock.connect((ip, port.number))

                # Récupérer les infos du certificat
                cert = ssock.getpeercert(binary_form=False)
                if cert:
                    # Extraire le CN du certificat
                    subject = dict(x[0] for x in cert.get("subject", []))
                    cn = subject.get("commonName", "")
                    if cn:
                        port.banner = f"TLS CN={cn}"

                # Envoyer une requête HTTP
                request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: WifiScanner/1.0\r\nConnection: close\r\n\r\n"
                ssock.send(request.encode())

                response = b""
                while True:
                    try:
                        chunk = ssock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                        if len(response) > 8192:
                            break
                    except socket.timeout:
                        break

                if response:
                    text = response.decode("utf-8", errors="replace")
                    port.service = "HTTPS"
                    self._parse_http_response(port, text)

        except (socket.timeout, ConnectionRefusedError, ssl.SSLError, OSError):
            port.service = "HTTPS"
        finally:
            pass

    def _parse_banner(self, port, banner):
        # Parse une bannière pour identifier le service et la version

        # SSH
        if banner.startswith("SSH-"):
            port.service = "SSH"
            match = re.search(r"SSH-[\d.]+-([\w._-]+)", banner)
            if match:
                port.version = match.group(1)
            return

        # FTP
        if re.match(r"^2[12]0[ -]", banner):
            port.service = "FTP"
            match = re.search(r"(\w+FTPd?|ProFTPD|vsftpd|FileZilla)[\s/]*([\d.]+)?", banner, re.IGNORECASE)
            if match:
                port.version = f"{match.group(1)} {match.group(2) or ''}".strip()
            return

        # SMTP
        if re.match(r"^220[ -]", banner):
            port.service = "SMTP"
            match = re.search(r"(Postfix|Sendmail|Exim|Exchange|hMailServer)[\s/]*([\d.]+)?", banner, re.IGNORECASE)
            if match:
                port.version = f"{match.group(1)} {match.group(2) or ''}".strip()
            return

        # POP3
        if banner.startswith("+OK"):
            port.service = "POP3"
            return

        # IMAP
        if "IMAP" in banner.upper():
            port.service = "IMAP"
            return

        # MySQL
        if "mysql" in banner.lower() or "mariadb" in banner.lower():
            port.service = "MySQL"
            match = re.search(r"([\d.]+)", banner)
            if match:
                port.version = match.group(1)
            return

        # Redis
        if "redis_version" in banner:
            port.service = "Redis"
            match = re.search(r"redis_version:([\d.]+)", banner)
            if match:
                port.version = match.group(1)
            return

        # Telnet
        if port.number == 23:
            port.service = "Telnet"
            return

        # VNC
        if banner.startswith("RFB"):
            port.service = "VNC"
            match = re.search(r"RFB ([\d.]+)", banner)
            if match:
                port.version = match.group(1)
            return

    def _parse_http_response(self, port, response):
        # Parse une réponse HTTP pour identifier le serveur et les technologies

        # Header Server
        match = re.search(r"^Server:\s*(.+)$", response, re.MULTILINE | re.IGNORECASE)
        if match:
            port.version = match.group(1).strip()

        # Header X-Powered-By
        match = re.search(r"^X-Powered-By:\s*(.+)$", response, re.MULTILINE | re.IGNORECASE)
        if match:
            powered_by = match.group(1).strip()
            port.version = f"{port.version} ({powered_by})" if port.version else powered_by

        # Titre de la page
        match = re.search(r"<title>([^<]+)</title>", response, re.IGNORECASE)
        if match:
            title = match.group(1).strip()
            if title:
                port.banner = f"Title: {title}"

        # Détection de panneaux d'admin
        admin_keywords = ["login", "admin", "dashboard", "management", "configuration",
                          "router", "gateway", "freebox", "livebox", "bbox"]
        response_lower = response.lower()
        for keyword in admin_keywords:
            if keyword in response_lower:
                if not port.banner or "admin" not in port.banner.lower():
                    port.banner = f"{port.banner} [Admin Panel]" if port.banner else "[Admin Panel]"
                break
