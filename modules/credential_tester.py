# credential_tester.py — Test des identifiants par défaut
# Teste les credentials par défaut sur les services détectés
# IMPORTANT : nécessite l'accord explicite de l'utilisateur

import socket
import ftplib

from core.models import Host, Vulnerability, Severity
from core.config import ScannerConfig


class CredentialTester:
    # Teste les identifiants par défaut sur les services détectés

    def __init__(self, config=None, logger=None):
        self.config = config or ScannerConfig()
        self.logger = logger
        self.credentials_db = self.config.load_vuln_db("default_credentials.json")

    def test_all_hosts(self, hosts):
        # Teste les identifiants par défaut sur tous les hôtes
        results = []
        for host in hosts:
            host_results = self._test_host(host)
            results.extend(host_results)
        return results

    def test_single_host(self, host):
        # Teste les identifiants par défaut sur un seul hôte
        return self._test_host(host)

    def _test_host(self, host):
        # Teste chaque service ouvert sur l'hôte
        results = []
        services_db = self.credentials_db.get("services", {})

        for port in host.open_ports:
            service_type = self._get_service_type(port)
            if not service_type:
                continue

            creds_list = services_db.get(service_type, [])
            if not creds_list:
                continue

            if self.logger:
                self.logger.info(f"Test des identifiants {service_type} sur {host.ip}:{port.number}")

            for creds in creds_list:
                success = self._test_credential(host.ip, port, service_type, creds)
                if success:
                    user = creds.get("user", creds.get("community", ""))
                    passwd = creds.get("pass", creds.get("community", ""))
                    proof = f"Identifiants valides : {user}:{passwd}" if user else f"Accès sans authentification"

                    vuln = Vulnerability(
                        name=f"Identifiants par défaut sur {service_type.upper()} ({host.ip}:{port.number})",
                        severity=Severity.CRITICAL,
                        description=f"Le service {service_type.upper()} accepte les identifiants par défaut. "
                                   "Un attaquant peut accéder au service sans effort.",
                        remediation=f"Changer immédiatement le mot de passe du service {service_type.upper()}. "
                                   "Utiliser un mot de passe fort et unique.",
                        host_ip=host.ip,
                        port=port.number,
                        proof=proof,
                    )
                    host.vulnerabilities.append(vuln)
                    results.append(vuln)

                    if self.logger:
                        self.logger.vuln("CRITIQUE",
                            f"{host.ip}:{port.number} — Identifiants par défaut trouvés ({service_type})")

                    # Un seul résultat positif par service suffit
                    break

        return results

    def _get_service_type(self, port):
        # Détermine le type de service à partir du port
        port_map = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            1883: "mqtt",
            3306: "mysql",
            5900: "vnc",
            5901: "vnc",
            6379: "redis",
            27017: "mongodb",
            161: "snmp",
        }
        return port_map.get(port.number, "")

    def _test_credential(self, ip, port, service_type, creds):
        # Teste un couple d'identifiants sur un service
        try:
            if service_type == "ftp":
                return self._test_ftp(ip, port.number, creds)
            elif service_type == "ssh":
                return self._test_ssh(ip, port.number, creds)
            elif service_type == "redis":
                return self._test_redis(ip, port.number, creds)
            elif service_type == "mysql":
                return self._test_mysql(ip, port.number, creds)
            elif service_type == "snmp":
                return self._test_snmp(ip, port.number, creds)
        except Exception:
            pass
        return False

    # --- Testeurs par protocole ---

    def _test_ftp(self, ip, port, creds):
        # Teste les identifiants FTP
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout=self.config.timeout * 4)
            ftp.login(creds.get("user", ""), creds.get("pass", ""))
            ftp.quit()
            return True
        except (ftplib.error_perm, ftplib.error_reply, OSError):
            return False

    def _test_ssh(self, ip, port, creds):
        # Teste les identifiants SSH via paramiko
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                ip, port=port,
                username=creds.get("user", ""),
                password=creds.get("pass", ""),
                timeout=self.config.timeout * 4,
                look_for_keys=False,
                allow_agent=False,
            )
            client.close()
            return True
        except ImportError:
            if self.logger:
                self.logger.warning("paramiko non installé — test SSH désactivé")
            return False
        except Exception:
            return False

    def _test_redis(self, ip, port, creds):
        # Teste l'accès Redis
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.config.timeout * 4)
        try:
            sock.connect((ip, port))
            password = creds.get("pass", "")

            if password:
                # Authentification
                sock.send(f"AUTH {password}\r\n".encode())
                response = sock.recv(1024).decode("utf-8", errors="replace")
                if "+OK" in response:
                    return True
            else:
                # Test sans mot de passe
                sock.send(b"PING\r\n")
                response = sock.recv(1024).decode("utf-8", errors="replace")
                if "+PONG" in response:
                    return True

        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()
        return False

    def _test_mysql(self, ip, port, creds):
        # Teste les identifiants MySQL basique (handshake)
        # Test simplifié sans dépendance mysql-connector
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.config.timeout * 4)
        try:
            sock.connect((ip, port))
            # Lire le paquet de greeting MySQL
            data = sock.recv(1024)
            if data and len(data) > 4:
                # Si on reçoit un greeting, le service est accessible
                # Un test complet nécessiterait un client MySQL
                return False
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()
        return False

    def _test_snmp(self, ip, port, creds):
        # Teste les community strings SNMP
        community = creds.get("community", "public")
        # Construire un paquet SNMP GET simple
        # OID : 1.3.6.1.2.1.1.1.0 (sysDescr)
        packet = (
            b"\x30\x26\x02\x01\x01\x04" +
            bytes([len(community)]) + community.encode() +
            b"\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00"
            b"\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06"
            b"\x01\x02\x01\x05\x00"
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.config.timeout * 2)
        try:
            sock.sendto(packet, (ip, port))
            data, _ = sock.recvfrom(1024)
            if data and len(data) > 10:
                return True
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()
        return False
