# routes_vulns.py — Routes API pour les vulnérabilités

from flask import Blueprint, jsonify

vulns_bp = Blueprint('vulns', __name__)


def _get_scan_state():
    from api.routes_scan import _scan_state
    return _scan_state


def _vuln_to_dict(vuln, default_ip=''):
    # Convertit une Vulnerability ou WifiVulnerability en dict sérialisable
    return {
        'name': vuln.name,
        'severity': vuln.severity.value,
        'description': vuln.description,
        'remediation': vuln.remediation,
        'host_ip': getattr(vuln, 'host_ip', '') or default_ip,
        'port': getattr(vuln, 'port', 0),
        'cve': getattr(vuln, 'cve', ''),
        'proof': getattr(vuln, 'proof', ''),
    }


@vulns_bp.route('/vulnerabilities')
def get_vulnerabilities():
    state = _get_scan_state()
    result = state.get('result')
    if not result:
        return jsonify([])

    try:
        all_vulns = []

        # Vulnérabilités globales (WiFi, DNS, trafic)
        for vuln in list(result.vulnerabilities):
            all_vulns.append(_vuln_to_dict(vuln))

        # Vulnérabilités par hôte
        hosts = list(result.hosts) if result.hosts else []
        for host in hosts:
            for vuln in list(host.vulnerabilities):
                all_vulns.append(_vuln_to_dict(vuln, host.ip))

        # Vulnérabilités WiFi
        if result.wifi_info and result.wifi_info.vulnerabilities:
            for vuln in list(result.wifi_info.vulnerabilities):
                all_vulns.append(_vuln_to_dict(vuln))

        # Trier par sévérité
        severity_order = {'CRITIQUE': 0, 'HAUTE': 1, 'MOYENNE': 2, 'FAIBLE': 3, 'INFO': 4}
        all_vulns.sort(key=lambda v: severity_order.get(v['severity'], 5))

        return jsonify(all_vulns)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
