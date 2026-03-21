# routes_radar.py — Routes API pour le module radar
# Gère le démarrage/arrêt du radar, les positions des appareils, et les pings

from flask import Blueprint, jsonify, request

radar_bp = Blueprint('radar', __name__)

_radar_engine = None
_scan_state = None
_events = None


def init_radar_routes(radar_engine, scan_state, events_instance):
    # Initialise les dépendances du module radar
    global _radar_engine, _scan_state, _events
    _radar_engine = radar_engine
    _scan_state = scan_state
    _events = events_instance


@radar_bp.route('/radar/devices')
def get_radar_devices():
    # Retourne la liste des appareils avec leurs positions
    if not _radar_engine:
        return jsonify([])
    devices = _radar_engine.get_devices()
    return jsonify(devices)


@radar_bp.route('/radar/start', methods=['POST'])
def start_radar():
    # Démarre le mode surveillance radar
    if not _radar_engine:
        return jsonify({'error': 'Radar non initialisé'}), 500

    if _radar_engine.is_running():
        return jsonify({'status': 'already_running'})

    # Charger les appareils depuis le dernier scan
    if _scan_state and _scan_state.get('result'):
        result = _scan_state['result']
        hosts = getattr(result, 'hosts', [])
        for host in hosts:
            device_type = _map_device_type(
                getattr(host, 'device_type', ''),
                getattr(host, 'is_gateway', False)
            )
            _radar_engine.add_device(
                ip=host.ip,
                mac=getattr(host, 'mac', ''),
                hostname=getattr(host, 'hostname', '') or host.ip,
                device_type=device_type,
            )

    _radar_engine.start()
    return jsonify({'status': 'started', 'devices': len(_radar_engine.get_devices())})


@radar_bp.route('/radar/stop', methods=['POST'])
def stop_radar():
    # Arrête le mode surveillance radar
    if not _radar_engine:
        return jsonify({'error': 'Radar non initialisé'}), 500
    _radar_engine.stop()
    return jsonify({'status': 'stopped'})


@radar_bp.route('/radar/status')
def radar_status():
    # Retourne l'état du radar + IP locale (réseau actif)
    import socket
    local_ip = ''
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass
    if not _radar_engine:
        return jsonify({'running': False, 'devices': 0, 'local_ip': local_ip})
    return jsonify({
        'running': _radar_engine.is_running(),
        'devices': len(_radar_engine.get_devices()),
        'local_ip': local_ip,
    })


@radar_bp.route('/radar/ping/<ip>', methods=['POST'])
def ping_device(ip):
    # Ping un appareil spécifique
    if not _radar_engine:
        return jsonify({'error': 'Radar non initialisé'}), 500
    result = _radar_engine.ping_device(ip)
    return jsonify(result)


@radar_bp.route('/radar/add', methods=['POST'])
def add_device():
    # Ajoute un appareil au radar manuellement
    if not _radar_engine:
        return jsonify({'error': 'Radar non initialisé'}), 500
    data = request.json or {}
    ip = data.get('ip', '')
    if not ip:
        return jsonify({'error': 'IP requise'}), 400
    device = _radar_engine.add_device(
        ip=ip,
        mac=data.get('mac', ''),
        hostname=data.get('hostname', ''),
        device_type=data.get('device_type', 'unknown'),
    )
    return jsonify(device.to_dict())


def _map_device_type(device_type, is_gateway):
    # Convertit le device_type du scan en type radar
    if is_gateway:
        return 'router'
    dt = (device_type or '').lower()
    mapping = {
        'routeur': 'router',
        'routeur/ap': 'router',
        'serveur': 'server',
        'pc/desktop': 'desktop',
        'pc': 'desktop',
        'desktop': 'desktop',
        'laptop': 'laptop',
        'iphone/ipad': 'phone',
        'iphone': 'phone',
        'android': 'phone',
        'smartphone': 'phone',
        'appareil mobile': 'mobile',
        'appareil mobile (mac privée)': 'mobile',
        'tablette': 'tablet',
        'imprimante': 'printer',
        'iot': 'iot',
        'caméra ip': 'camera',
        'nas': 'server',
    }
    for key, val in mapping.items():
        if key in dt:
            return val
    return 'unknown'
