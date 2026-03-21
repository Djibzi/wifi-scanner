# modules — Redirige vers les modules de scan à la racine du projet
import sys
import os

_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
if _root not in sys.path:
    sys.path.insert(0, _root)

from modules.wifi_analyzer import WifiAnalyzer
from modules.host_discovery import HostDiscovery, OUILookup
from modules.port_scanner import PortScanner
from modules.service_detector import ServiceDetector
from modules.os_fingerprinter import OSFingerprinter
from modules.vuln_detector import VulnDetector
from modules.credential_tester import CredentialTester
from modules.dns_analyzer import DNSAnalyzer
from modules.traffic_analyzer import TrafficAnalyzer
