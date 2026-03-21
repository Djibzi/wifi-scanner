# routes_scan.py — Routes API pour le scan réseau

import threading
import time
from datetime import datetime

from flask import Blueprint, jsonify, request

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

scan_bp = Blueprint('scan', __name__)

# Injectés par init_scan_routes
_scan_state = None
_db = None
_events = None


def init_scan_routes(scan_state, db, events):
    global _scan_state, _db, _events
    _scan_state = scan_state
    _db = db
    _events = events


@scan_bp.route('/scan/start', methods=['POST'])
def start_scan():
    if _scan_state['running']:
        return jsonify({'error': 'Un scan est déjà en cours'}), 409

    data = request.get_json() or {}
    mode = data.get('mode', 'quick')
    target = data.get('target', '')

    # Lancer le scan dans un thread séparé
    thread = threading.Thread(target=_run_scan, args=(mode, target), daemon=True)
    thread.start()

    return jsonify({'status': 'started', 'mode': mode, 'target': target})


@scan_bp.route('/scan/stop', methods=['POST'])
def stop_scan():
    _scan_state['running'] = False
    return jsonify({'status': 'stopped'})


@scan_bp.route('/scan/status')
def scan_status():
    return jsonify({
        'running': _scan_state['running'],
        'progress': _scan_state['progress'],
        'current_module': _scan_state['current_module'],
    })


def _run_scan(mode, target):
    # Exécution du scan complet en arrière-plan
    _scan_state['running'] = True
    _scan_state['progress'] = 0
    _scan_state['start_time'] = time.time()

    config = ScannerConfig()
    config.scan_mode = mode
    if target:
        config.target = target
    logger = ScannerLogger(verbose=True)

    result = ScanResult()
    result.scan_mode = mode
    result.scan_start = datetime.now().isoformat()

    modules = [
        ('WiFi', 10, _scan_wifi),
        ('Découverte', 25, _scan_hosts),
        ('Ports', 45, _scan_ports),
        ('Services', 60, _scan_services),
        ('OS', 70, _scan_os),
        ('Vulnérabilités', 85, _scan_vulns),
        ('DNS', 95, _scan_dns),
    ]

    _events.scan_started(mode, target)

    try:
        for name, progress, func in modules:
            if not _scan_state['running']:
                break

            _scan_state['current_module'] = name
            _scan_state['progress'] = progress
            _events.scan_progress(name, progress, f'Module {name} en cours...')
            _events.log('info', f'--- {name} ---')

            start = time.time()
            func(config, logger, result)
            duration = time.time() - start

            _events.scan_module_complete(name, round(duration, 2))
            _events.log('info', f'{name} terminé en {duration:.1f}s')

    except Exception as e:
        _events.log('error', f'Erreur : {str(e)}')

    result.scan_end = datetime.now().isoformat()
    _scan_state['result'] = result
    _scan_state['progress'] = 100
    _scan_state['running'] = False

    score = result.get_security_score()
    grade = result.get_grade()
    duration = time.time() - _scan_state['start_time']

    _events.scan_finished(score, grade, round(duration, 2))

    # Sauvegarder en base
    _db.save_scan({
        'mode': mode,
        'target': target,
        'duration': round(duration, 2),
        'score': score,
        'grade': grade,
        'hosts_count': len(result.hosts),
        'vulns_count': len(result.vulnerabilities) + sum(
            len(h.vulnerabilities) for h in result.hosts
        ),
    })


# --- Fonctions de scan par module ---

def _scan_wifi(config, logger, result):
    analyzer = WifiAnalyzer(config=config, logger=logger)
    wifi_info = analyzer.analyze()
    result.wifi_info = wifi_info
    if wifi_info and wifi_info.ssid:
        _events.log('info', f'WiFi : {wifi_info.ssid} ({wifi_info.security})')


def _scan_hosts(config, logger, result):
    discovery = HostDiscovery(config=config, logger=logger)
    hosts = discovery.discover()
    result.hosts = hosts
    for host in hosts:
        _events.host_found({
            'ip': host.ip,
            'mac': host.mac,
            'vendor': host.vendor,
            'hostname': host.hostname,
        })


def _scan_ports(config, logger, result):
    if not result.hosts:
        return
    scanner = PortScanner(config=config, logger=logger)
    for host in result.hosts:
        scanner.scan_single_host(host)
        for port in host.open_ports:
            _events.port_found(host.ip, port.number, port.service)


def _scan_services(config, logger, result):
    if not result.hosts:
        return
    detector = ServiceDetector(config=config, logger=logger)
    for host in result.hosts:
        if host.open_ports:
            detector.detect_single_host(host)


def _scan_os(config, logger, result):
    if not result.hosts:
        return
    fingerprinter = OSFingerprinter(config=config, logger=logger)
    for host in result.hosts:
        fingerprinter.fingerprint_single(host)

    # Re-enrichir les types d'appareils avec les ports + OS maintenant connus
    from modules.host_discovery import OUILookup
    oui = OUILookup()
    for host in result.hosts:
        if host.device_type in ("Inconnu", "", "Appareil mobile (MAC privée)", "Smartphone (MAC privée)"):
            port_numbers = [p.number for p in host.open_ports] if host.open_ports else []
            new_type = oui.guess_device_type(
                host.vendor, port_numbers, host.os_guess, host.hostname
            )
            if new_type != "Inconnu":
                host.device_type = new_type


def _scan_vulns(config, logger, result):
    if not result.hosts:
        return
    detector = VulnDetector(config=config, logger=logger)
    for host in result.hosts:
        vulns = detector.detect_single(host)
        # detect_single ajoute déjà les vulns dans host.vulnerabilities
        for vuln in vulns:
            _events.vuln_found({
                'name': vuln.name,
                'severity': vuln.severity.value,
                'host_ip': vuln.host_ip,
                'port': vuln.port,
            })


def _scan_dns(config, logger, result):
    analyzer = DNSAnalyzer(config=config, logger=logger)
    wifi = result.wifi_info
    vulns = analyzer.analyze(wifi_info=wifi, hosts=result.hosts)
    result.vulnerabilities.extend(vulns)
