# wifi_scanner.py — Point d'entrée principal (CLI)
# Usage :
#   python wifi_scanner.py                       # Scan rapide
#   python wifi_scanner.py --full                 # Scan complet
#   python wifi_scanner.py --target 192.168.1.10  # Scanner un appareil
#   python wifi_scanner.py --wifi-only            # Analyser uniquement le WiFi
#   python wifi_scanner.py --passive              # Mode passif uniquement
#   python wifi_scanner.py --creds                # Tester les identifiants par défaut
#   python wifi_scanner.py --report html          # Format du rapport
#   python wifi_scanner.py --output rapport.html  # Fichier de sortie

import argparse
import sys
import time

from core.config import ScannerConfig
from core.logger import ScannerLogger
from core.models import ScanResult
from modules.wifi_analyzer import WifiAnalyzer
from modules.host_discovery import HostDiscovery
from modules.port_scanner import PortScanner
from modules.service_detector import ServiceDetector
from modules.os_fingerprinter import OSFingerprinter
from modules.vuln_detector import VulnDetector
from modules.credential_tester import CredentialTester
from modules.dns_analyzer import DNSAnalyzer
from modules.traffic_analyzer import TrafficAnalyzer
from reports.generator import ReportGenerator


class WifiScannerCLI:
    # Interface en ligne de commande du scanner réseau WiFi

    BANNER = r"""
 __        ___ _____ _   ____
 \ \      / (_)  ___(_) / ___|  ___ __ _ _ __  _ __   ___ _ __
  \ \ /\ / /| | |_  | | \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
   \ V  V / | |  _| | |  ___) | (_| (_| | | | | | | |  __/ |
    \_/\_/  |_|_|   |_| |____/ \___\__,_|_| |_|_| |_|\___|_|
    """

    def __init__(self):
        self.config = ScannerConfig()
        self.logger = None
        self.result = ScanResult()

    def parse_args(self):
        # Parse les arguments de la ligne de commande
        parser = argparse.ArgumentParser(
            description="Scanner de réseau WiFi — Analyse et détection de vulnérabilités"
        )

        # Mode de scan
        parser.add_argument("--full", action="store_true", help="Scan complet (top 1000 ports)")
        parser.add_argument("--exhaustive", action="store_true", help="Scan exhaustif (65535 ports)")
        parser.add_argument("--target", type=str, help="Scanner un appareil spécifique (IP)")
        parser.add_argument("--wifi-only", action="store_true", help="Analyser uniquement le WiFi")
        parser.add_argument("--passive", action="store_true", help="Mode passif uniquement (écoute)")
        parser.add_argument("--creds", action="store_true", help="Tester les identifiants par défaut")

        # Rapport
        parser.add_argument("--report", type=str, default="html", choices=["html", "md", "json"],
                            help="Format du rapport (défaut: html)")
        parser.add_argument("--output", "-o", type=str, help="Fichier de sortie du rapport")

        # Options
        parser.add_argument("--timeout", type=float, help="Timeout des connexions en secondes")
        parser.add_argument("--threads", type=int, help="Nombre de threads pour le scan")
        parser.add_argument("--interface", "-i", type=str, help="Interface réseau à utiliser")
        parser.add_argument("--verbose", "-v", action="store_true", help="Mode verbeux")
        parser.add_argument("--debug", action="store_true", help="Mode debug")

        args = parser.parse_args()

        # Appliquer les arguments à la config
        if args.full:
            self.config.set_scan_mode("full")
        elif args.exhaustive:
            self.config.set_scan_mode("exhaustive")

        if args.target:
            self.config.target = args.target
        if args.wifi_only:
            self.config.wifi_only = True
        if args.passive:
            self.config.passive_mode = True
        if args.creds:
            self.config.test_credentials = True

        self.config.report_format = args.report
        if args.output:
            self.config.output_file = args.output

        if args.timeout:
            self.config.timeout = args.timeout
        if args.threads:
            self.config.max_threads = args.threads
        if args.interface:
            self.config.interface = args.interface

        self.config.verbose = args.verbose
        self.config.debug = args.debug

        return args

    def setup(self):
        # Initialise le logger et affiche la bannière
        self.logger = ScannerLogger(
            verbose=self.config.verbose,
            debug=self.config.debug
        )
        print(self.BANNER)
        print(f"  Mode de scan : {self.config.scan_mode}")
        if self.config.target:
            print(f"  Cible        : {self.config.target}")
        print(f"  Threads      : {self.config.max_threads}")
        print(f"  Timeout      : {self.config.timeout}s")
        print(f"  Rapport      : {self.config.report_format}")
        print()

    def run(self):
        # Exécute le scan complet selon la configuration
        self.parse_args()
        self.setup()

        start_time = time.time()
        self.result = ScanResult(scan_mode=self.config.scan_mode)

        try:
            # Étape 1 — Analyse WiFi
            self.logger.scan_start("Analyse WiFi")
            self._run_wifi_analysis()
            self.logger.scan_end("Analyse WiFi", time.time() - start_time)

            if self.config.wifi_only:
                self._generate_report()
                return

            # Étape 2 — Découverte des hôtes
            if not self.config.passive_mode:
                self.logger.scan_start("Découverte des hôtes")
                self._run_host_discovery()
                self.logger.scan_end("Découverte des hôtes", time.time() - start_time)

                # Étape 3 — Scan de ports
                self.logger.scan_start("Scan de ports")
                self._run_port_scan()
                self.logger.scan_end("Scan de ports", time.time() - start_time)

                # Étape 4 — Détection des services
                self.logger.scan_start("Détection des services")
                self._run_service_detection()
                self.logger.scan_end("Détection des services", time.time() - start_time)

                # Étape 5 — Fingerprint OS
                self.logger.scan_start("Fingerprint OS")
                self._run_os_fingerprint()
                self.logger.scan_end("Fingerprint OS", time.time() - start_time)

                # Étape 6 — Détection de vulnérabilités
                self.logger.scan_start("Détection de vulnérabilités")
                self._run_vuln_detection()
                self.logger.scan_end("Détection de vulnérabilités", time.time() - start_time)

                # Étape 7 — Test des identifiants (optionnel)
                if self.config.test_credentials:
                    self.logger.scan_start("Test des identifiants")
                    self._run_credential_test()
                    self.logger.scan_end("Test des identifiants", time.time() - start_time)

            # Étape 8 — Analyse passive du trafic (optionnel)
            if self.config.passive_mode:
                self.logger.scan_start("Analyse passive du trafic")
                self._run_traffic_analysis()
                self.logger.scan_end("Analyse passive du trafic", time.time() - start_time)

            # Étape 9 — Génération du rapport
            self.result.finalize()
            self._generate_report()

        except KeyboardInterrupt:
            print("\n[!] Scan interrompu par l'utilisateur.")
            self.result.finalize()
            self._generate_report()

        except PermissionError:
            print("\n[!] Erreur : certaines fonctions nécessitent les droits administrateur.")
            print("    Relancez avec : sudo python wifi_scanner.py" if sys.platform != "win32"
                  else "    Relancez en tant qu'administrateur.")

        duration = time.time() - start_time
        print(f"\n[*] Scan terminé en {duration:.2f} secondes.")
        print(f"[*] Score de sécurité : {self.result.get_security_score()}/100 ({self.result.get_grade()})")
        print(f"[*] Vulnérabilités trouvées : {self.result.get_total_vulns()}")

    # --- Méthodes de scan (stubs pour les modules à venir) ---

    def _run_wifi_analysis(self):
        # Analyse le réseau WiFi et détecte les vulnérabilités
        analyzer = WifiAnalyzer(config=self.config, logger=self.logger)
        self.result.wifi_info = analyzer.analyze()

        # Afficher un résumé
        wifi = self.result.wifi_info
        if wifi.ssid:
            print(f"  [+] SSID        : {wifi.ssid}")
            print(f"  [+] BSSID       : {wifi.bssid}")
            print(f"  [+] Sécurité    : {wifi.security} / {wifi.encryption}")
            print(f"  [+] Canal       : {wifi.channel} ({wifi.frequency})")
            print(f"  [+] Signal      : {wifi.signal_strength} dBm")
            print(f"  [+] Passerelle  : {wifi.gateway_ip}")
            print(f"  [+] Masque      : {wifi.subnet_mask}")
            print(f"  [+] DNS         : {', '.join(wifi.dns_servers)}")
            if wifi.vulnerabilities:
                print(f"  [!] {len(wifi.vulnerabilities)} vulnérabilité(s) WiFi détectée(s)")
                for vuln in wifi.vulnerabilities:
                    print(f"      [{vuln.severity.value}] {vuln.name}")
            else:
                print("  [+] Aucune vulnérabilité WiFi détectée")
        else:
            print("  [-] Impossible de récupérer les infos WiFi")
        print()

    def _run_host_discovery(self):
        # Découvre tous les appareils connectés au réseau
        # Si une cible est spécifiée, créer directement l'hôte sans scanner tout le réseau
        if self.config.target:
            from core.models import Host
            target_host = Host(ip=self.config.target)
            self.result.hosts = [target_host]
            if self.logger:
                self.logger.info(f"Cible spécifiée : {self.config.target}")
        else:
            discovery = HostDiscovery(config=self.config, logger=self.logger)
            gateway_ip = self.result.wifi_info.gateway_ip if self.result.wifi_info else None
            subnet_mask = self.result.wifi_info.subnet_mask if self.result.wifi_info else None
            self.result.hosts = discovery.discover(gateway_ip=gateway_ip, subnet_mask=subnet_mask)

        # Afficher un résumé
        print(f"  [+] {len(self.result.hosts)} appareil(s) découvert(s) :")
        for host in self.result.hosts:
            gw_tag = " [GATEWAY]" if host.is_gateway else ""
            vendor_tag = f" ({host.vendor})" if host.vendor else ""
            hostname_tag = f" - {host.hostname}" if host.hostname else ""
            print(f"      {host.ip:15s}  {host.mac:17s}{vendor_tag}{hostname_tag}{gw_tag}")
        print()

    def _run_port_scan(self):
        # Scanne les ports ouverts sur chaque hôte
        if not self.result.hosts:
            return
        scanner = PortScanner(config=self.config, logger=self.logger)
        scanner.scan_hosts(self.result.hosts)

        # Afficher un résumé
        for host in self.result.hosts:
            if host.open_ports:
                ports_str = ", ".join(
                    f"{p.number}/{p.service}" for p in host.open_ports
                )
                print(f"  [+] {host.ip:15s} — {len(host.open_ports)} port(s) : {ports_str}")
        print()

    def _run_service_detection(self):
        # Identifie les services et versions sur les ports ouverts
        if not self.result.hosts:
            return
        detector = ServiceDetector(config=self.config, logger=self.logger)
        detector.detect_services(self.result.hosts)

        # Afficher un résumé
        for host in self.result.hosts:
            for port in host.open_ports:
                if port.version:
                    print(f"  [+] {host.ip}:{port.number} — {port.service} {port.version}")
        print()

    def _run_os_fingerprint(self):
        # Estime le système d'exploitation de chaque hôte
        if not self.result.hosts:
            return
        fingerprinter = OSFingerprinter(config=self.config, logger=self.logger)
        fingerprinter.fingerprint_hosts(self.result.hosts)

        # Afficher un résumé
        for host in self.result.hosts:
            if host.os_guess:
                print(f"  [+] {host.ip:15s} — {host.os_guess} ({host.device_type})")
        print()

    def _run_vuln_detection(self):
        # Détecte les vulnérabilités + analyse DNS
        if not self.result.hosts:
            return

        # Détection de vulnérabilités sur les hôtes
        detector = VulnDetector(config=self.config, logger=self.logger)
        detector.detect_all(self.result.hosts, wifi_info=self.result.wifi_info)

        # Analyse DNS
        dns_analyzer = DNSAnalyzer(config=self.config, logger=self.logger)
        dns_vulns = dns_analyzer.analyze(
            wifi_info=self.result.wifi_info,
            hosts=self.result.hosts,
        )
        self.result.vulnerabilities.extend(dns_vulns)

        # Afficher un résumé
        total = sum(len(h.vulnerabilities) for h in self.result.hosts) + len(dns_vulns)
        if total > 0:
            print(f"  [!] {total} vulnérabilité(s) détectée(s) :")
            for host in self.result.hosts:
                for vuln in host.vulnerabilities:
                    print(f"      [{vuln.severity.value:8s}] {host.ip}:{vuln.port} — {vuln.name}")
            for vuln in dns_vulns:
                print(f"      [{vuln.severity.value:8s}] DNS — {vuln.name}")
        else:
            print("  [+] Aucune vulnérabilité détectée")
        print()

    def _run_credential_test(self):
        # Teste les identifiants par défaut sur les services détectés
        if not self.result.hosts:
            return
        tester = CredentialTester(config=self.config, logger=self.logger)
        results = tester.test_all_hosts(self.result.hosts)

        if results:
            print(f"  [!!!] {len(results)} identifiant(s) par défaut trouvé(s) :")
            for vuln in results:
                print(f"      [{vuln.severity.value}] {vuln.host_ip}:{vuln.port} — {vuln.proof}")
        else:
            print("  [+] Aucun identifiant par défaut trouvé")
        print()

    def _run_traffic_analysis(self):
        # Écoute passive du trafic réseau
        analyzer = TrafficAnalyzer(config=self.config, logger=self.logger, duration=30)
        traffic_vulns = analyzer.analyze()
        self.result.vulnerabilities.extend(traffic_vulns)

        # Afficher un résumé
        summary = analyzer.get_summary()
        print(f"  [*] {summary['packets']} paquets capturés en 30s")
        if summary["unencrypted_protocols"]:
            print(f"  [!] Protocoles non chiffrés : {', '.join(summary['unencrypted_protocols'])}")
        if summary["arp_anomalies"] > 0:
            print(f"  [!!!] {summary['arp_anomalies']} anomalie(s) ARP détectée(s)")
        if summary["top_talkers"]:
            print("  [*] Top appareils (trafic) :")
            for ip, bytes_count in summary["top_talkers"][:5]:
                print(f"      {ip:15s} — {bytes_count // 1024} Ko")
        print()

    def _generate_report(self):
        # Génère le rapport final
        generator = ReportGenerator(config=self.config, logger=self.logger)
        output_file = generator.generate(self.result)
        print(f"  [+] Rapport généré : {output_file}")


# --- Point d'entrée ---
if __name__ == "__main__":
    scanner = WifiScannerCLI()
    scanner.run()
