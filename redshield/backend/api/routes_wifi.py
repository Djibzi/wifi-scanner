# routes_wifi.py — Routes API pour les infos WiFi

from flask import Blueprint, jsonify

wifi_bp = Blueprint('wifi', __name__)


def _get_scan_state():
    from api.routes_scan import _scan_state
    return _scan_state


@wifi_bp.route('/wifi')
def get_wifi():
    state = _get_scan_state()
    result = state.get('result')

    if not result or not result.wifi_info:
        return jsonify({
            'ssid': '',
            'bssid': '',
            'security': '',
            'encryption': '',
            'channel': 0,
            'frequency': '',
            'signal_strength': 0,
            'gateway_ip': '',
            'subnet_mask': '',
            'dns_servers': [],
            'vulnerabilities': [],
        })

    wifi = result.wifi_info
    return jsonify({
        'ssid': wifi.ssid,
        'bssid': wifi.bssid,
        'security': wifi.security,
        'encryption': wifi.encryption,
        'channel': wifi.channel,
        'frequency': wifi.frequency,
        'signal_strength': wifi.signal_strength,
        'gateway_ip': wifi.gateway_ip,
        'subnet_mask': wifi.subnet_mask,
        'dns_servers': wifi.dns_servers,
        'vulnerabilities': [
            {
                'name': v.name,
                'severity': v.severity.value,
                'description': v.description,
                'remediation': v.remediation,
            }
            for v in wifi.vulnerabilities
        ],
    })
