# routes_hosts.py — Routes API pour les appareils

from flask import Blueprint, jsonify

hosts_bp = Blueprint('hosts', __name__)


def _get_scan_state():
    # Importer ici pour éviter les imports circulaires
    from api.routes_scan import _scan_state
    return _scan_state


def _host_to_dict(host):
    return {
        'ip': host.ip,
        'mac': host.mac,
        'vendor': host.vendor,
        'hostname': host.hostname,
        'os_guess': host.os_guess,
        'device_type': host.device_type,
        'is_gateway': host.is_gateway,
        'open_ports': [
            {
                'number': p.number,
                'protocol': p.protocol.value,
                'service': p.service,
                'version': p.version,
                'banner': p.banner,
            }
            for p in host.open_ports
        ],
        'vulnerabilities': [
            {
                'name': v.name,
                'severity': v.severity.value,
                'description': v.description,
                'remediation': v.remediation,
                'port': v.port,
                'cve': v.cve,
                'proof': v.proof,
            }
            for v in host.vulnerabilities
        ],
    }


@hosts_bp.route('/hosts')
def get_hosts():
    state = _get_scan_state()
    result = state.get('result')
    if not result or not result.hosts:
        return jsonify([])
    return jsonify([_host_to_dict(h) for h in result.hosts])


@hosts_bp.route('/hosts/<ip>')
def get_host(ip):
    state = _get_scan_state()
    result = state.get('result')
    if not result or not result.hosts:
        return jsonify({'error': 'Aucun scan disponible'}), 404

    for host in result.hosts:
        if host.ip == ip:
            return jsonify(_host_to_dict(host))

    return jsonify({'error': f'Hôte {ip} non trouvé'}), 404
