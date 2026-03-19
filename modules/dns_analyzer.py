# dns_analyzer.py — Analyse DNS du réseau
# Vérifie la configuration DNS, détecte les anomalies et le DNS rebinding

import socket
import struct
import time
import re

from core.models import Vulnerability, Severity
from core.config import ScannerConfig


class DNSAnalyzer:
    # Analyse la configuration DNS du réseau et détecte les anomalies

    def __init__(self, config=None, logger=None):
        self.config = config or ScannerConfig()
        self.logger = logger

    def analyze(self, wifi_info=None, hosts=None):
        # Lance l'analyse DNS complète
        vulnerabilities = []

        if wifi_info:
            # Vérifier les serveurs DNS configurés
            vulnerabilities.extend(self._check_dns_servers(wifi_info))

            # Vérifier le DNS rebinding sur la gateway
            if wifi_info.gateway_ip:
                vulnerabilities.extend(self._check_dns_rebinding(wifi_info.gateway_ip))

            # Vérifier si le DNS supporte DNSSEC
            vulnerabilities.extend(self._check_dnssec(wifi_info.dns_servers))

        # Vérifier les réponses DNS suspectes
        vulnerabilities.extend(self._check_dns_interception())

        if self.logger:
            self.logger.info(f"Analyse DNS : {len(vulnerabilities)} problème(s) détecté(s)")

        return vulnerabilities

    # --- Vérification des serveurs DNS ---

    def _check_dns_servers(self, wifi_info):
        # Vérifie que les DNS sont de confiance
        vulns = []

        if not wifi_info.dns_servers:
            vulns.append(Vulnerability(
                name="Aucun serveur DNS détecté",
                severity=Severity.MEDIUM,
                description="Aucun serveur DNS n'a été détecté dans la configuration réseau.",
                remediation="Configurer un DNS de confiance (1.1.1.1, 8.8.8.8, 9.9.9.9).",
            ))
            return vulns

        for dns in wifi_info.dns_servers:
            # Tester si le DNS répond
            if not self._dns_responds(dns):
                vulns.append(Vulnerability(
                    name=f"Serveur DNS ne répond pas : {dns}",
                    severity=Severity.LOW,
                    description=f"Le serveur DNS {dns} ne répond pas aux requêtes.",
                    remediation="Vérifier la configuration DNS ou changer de serveur.",
                ))
                continue

            # Mesurer le temps de réponse
            response_time = self._measure_dns_latency(dns)
            if response_time and response_time > 500:
                vulns.append(Vulnerability(
                    name=f"DNS lent : {dns} ({response_time:.0f}ms)",
                    severity=Severity.LOW,
                    description=f"Le serveur DNS {dns} a un temps de réponse élevé ({response_time:.0f}ms). "
                               "Cela peut ralentir la navigation.",
                    remediation="Utiliser un DNS plus rapide (1.1.1.1, 8.8.8.8).",
                ))

        return vulns

    # --- DNS Rebinding ---

    def _check_dns_rebinding(self, gateway_ip):
        # Vérifie si le routeur est vulnérable au DNS rebinding
        # Le DNS rebinding permet à un site malveillant d'accéder à l'interface du routeur
        vulns = []

        # Tester si le routeur répond aux requêtes HTTP avec un Host arbitraire
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((gateway_ip, 80))

            # Envoyer une requête avec un Host externe (simule un DNS rebinding)
            request = (
                "GET / HTTP/1.1\r\n"
                "Host: evil.attacker.com\r\n"
                "User-Agent: WifiScanner/1.0\r\n"
                "Connection: close\r\n\r\n"
            )
            sock.send(request.encode())

            response = sock.recv(4096).decode("utf-8", errors="replace")
            sock.close()

            # Si le routeur répond normalement à un Host externe, il est vulnérable
            if "200" in response[:20] or "301" in response[:20] or "302" in response[:20]:
                vulns.append(Vulnerability(
                    name="Routeur potentiellement vulnérable au DNS Rebinding",
                    severity=Severity.MEDIUM,
                    description="Le routeur répond aux requêtes HTTP avec un en-tête Host arbitraire. "
                               "Un site web malveillant pourrait exploiter le DNS rebinding pour "
                               "accéder à l'interface d'administration du routeur.",
                    remediation="Mettre à jour le firmware du routeur. Certains routeurs récents "
                               "bloquent les requêtes avec un Host non reconnu.",
                    host_ip=gateway_ip,
                    port=80,
                ))

        except (socket.timeout, ConnectionRefusedError, OSError):
            pass

        return vulns

    # --- DNSSEC ---

    def _check_dnssec(self, dns_servers):
        # Vérifie si les serveurs DNS supportent DNSSEC
        vulns = []

        if not dns_servers:
            return vulns

        dns = dns_servers[0]
        if not self._supports_dnssec(dns):
            vulns.append(Vulnerability(
                name="DNSSEC non activé",
                severity=Severity.LOW,
                description="Le serveur DNS ne semble pas valider les réponses DNSSEC. "
                           "Sans DNSSEC, les réponses DNS peuvent être falsifiées (DNS spoofing).",
                remediation="Utiliser un résolveur DNS qui supporte DNSSEC "
                           "(1.1.1.1, 8.8.8.8, 9.9.9.9 supportent tous DNSSEC).",
            ))

        return vulns

    # --- Interception DNS ---

    def _check_dns_interception(self):
        # Vérifie si les requêtes DNS sont interceptées (transparent DNS proxy)
        vulns = []

        # Envoyer une requête DNS à un IP qui n'est PAS un serveur DNS
        # Si on reçoit une réponse, c'est que le trafic DNS est intercepté
        test_ip = "198.51.100.1"  # IP de test RFC 5737 (ne devrait pas répondre)
        try:
            result = self._dns_query(test_ip, "example.com")
            if result:
                vulns.append(Vulnerability(
                    name="Interception DNS détectée (transparent proxy)",
                    severity=Severity.MEDIUM,
                    description="Les requêtes DNS semblent être interceptées et redirigées "
                               "par un proxy transparent. Cela signifie que votre FAI ou le réseau "
                               "peut surveiller et modifier vos requêtes DNS.",
                    remediation="Utiliser DNS over HTTPS (DoH) ou DNS over TLS (DoT) "
                               "pour chiffrer les requêtes DNS.",
                ))
        except Exception:
            pass

        return vulns

    # --- Utilitaires DNS ---

    def _dns_responds(self, dns_server):
        # Vérifie si un serveur DNS répond
        try:
            result = self._dns_query(dns_server, "google.com")
            return result is not None
        except Exception:
            return False

    def _measure_dns_latency(self, dns_server):
        # Mesure le temps de réponse DNS en millisecondes
        try:
            start = time.time()
            self._dns_query(dns_server, "google.com")
            return (time.time() - start) * 1000
        except Exception:
            return None

    def _supports_dnssec(self, dns_server):
        # Vérifie basiquement si le DNS supporte DNSSEC
        # Envoie une requête avec le flag DO (DNSSEC OK)
        try:
            result = self._dns_query(dns_server, "example.com", dnssec=True)
            return result is not None
        except Exception:
            return False

    def _dns_query(self, dns_server, domain, dnssec=False, timeout=3):
        # Envoie une requête DNS brute et retourne la réponse
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        try:
            # Construire une requête DNS
            packet = self._build_dns_query(domain, dnssec)
            sock.sendto(packet, (dns_server, 53))
            data, _ = sock.recvfrom(1024)

            if data and len(data) > 12:
                # Vérifier le code de réponse (RCODE)
                rcode = data[3] & 0x0F
                if rcode == 0:  # NOERROR
                    return data
            return None

        except (socket.timeout, OSError):
            return None
        finally:
            sock.close()

    def _build_dns_query(self, domain, dnssec=False):
        # Construit un paquet DNS query
        # Header
        transaction_id = b"\xaa\xbb"
        flags = b"\x01\x20" if dnssec else b"\x01\x00"  # RD=1, DO=1 si DNSSEC
        questions = b"\x00\x01"
        answer_rrs = b"\x00\x00"
        authority_rrs = b"\x00\x00"
        additional_rrs = b"\x00\x01" if dnssec else b"\x00\x00"

        header = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs

        # Question section
        qname = b""
        for part in domain.split("."):
            qname += bytes([len(part)]) + part.encode()
        qname += b"\x00"

        qtype = b"\x00\x01"   # A record
        qclass = b"\x00\x01"  # IN

        query = header + qname + qtype + qclass

        # OPT record pour DNSSEC
        if dnssec:
            # OPT pseudo-RR avec DO bit
            opt = b"\x00"            # Name (root)
            opt += b"\x00\x29"       # Type OPT
            opt += b"\x10\x00"       # UDP payload size 4096
            opt += b"\x00\x00"       # Extended RCODE
            opt += b"\x80\x00"       # EDNS flags (DO=1)
            opt += b"\x00\x00"       # RDLENGTH 0
            query += opt

        return query
