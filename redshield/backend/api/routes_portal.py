# routes_portal.py — Routes API pour le module Portail Captif
# Détection, analyse des clients, MAC spoofing et audit de sécurité

import threading

from flask import Blueprint, jsonify, request

portal_bp = Blueprint('portal', __name__)

_events = None
_detector = None
_client_hunter = None
_mac_spoofer = None
_auditor = None

# Cache du dernier résultat de détection
_last_detect_result = None


def init_portal_routes(events):
    """Initialise les routes du portail avec les dépendances."""
    global _events, _detector, _client_hunter, _mac_spoofer, _auditor

    _events = events

    from modules.portal_detector import PortalDetector
    from modules.portal_client_hunter import PortalClientHunter
    from modules.portal_mac_spoofer import PortalMacSpoofer
    from modules.portal_auditor import PortalAuditor

    _detector = PortalDetector()
    _client_hunter = PortalClientHunter(events=events)
    _mac_spoofer = PortalMacSpoofer(events=events)
    _auditor = PortalAuditor(events=events)


# --- Détection ---

@portal_bp.route('/portal/detect', methods=['GET'])
def detect_portal():
    """
    Lance une détection de portail captif.
    Analyse le réseau et retourne les résultats complets.
    """
    global _last_detect_result

    if _events:
        _events.log('info', 'Détection de portail captif...')

    try:
        result = _detector.detect()
        _last_detect_result = result

        # Émettre un événement si portail détecté
        if result.get('detected') and _events:
            _events.emit('portal:detected', {
                'type': result.get('type'),
                'portal_ip': result.get('portal_ip'),
                'status': result.get('portal_status'),
            })

        return jsonify(result)

    except Exception as e:
        if _events:
            _events.log('error', f'Erreur détection portail : {e}')
        return jsonify({'error': str(e), 'detected': False}), 500


# --- Clients ---

@portal_bp.route('/portal/clients', methods=['GET'])
def get_clients():
    """Liste des appareils avec leur statut d'autorisation."""
    try:
        clients = _client_hunter.get_clients()
        return jsonify(clients)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@portal_bp.route('/portal/clients/refresh', methods=['POST'])
def refresh_clients():
    """Relance l'écoute du trafic pour mettre à jour les statuts."""
    data = request.get_json(silent=True) or {}
    duration = int(data.get('duration', 30))
    duration = max(5, min(duration, 120))  # Limiter entre 5 et 120 secondes

    if _client_hunter._running:
        _client_hunter.stop()

    if _events:
        _events.log('info', f'Écoute du trafic portail ({duration}s)...')

    thread = threading.Thread(
        target=_client_hunter.start,
        args=(duration,),
        daemon=True,
    )
    thread.start()

    return jsonify({'status': 'started', 'duration': duration})


# --- MAC Spoofing ---

@portal_bp.route('/portal/mac/current', methods=['GET'])
def get_current_mac():
    """Retourne la MAC actuelle de l'interface réseau principale."""
    try:
        result = _mac_spoofer.get_current_mac()
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@portal_bp.route('/portal/mac/spoof', methods=['POST'])
def spoof_mac():
    """
    Change la MAC de l'interface réseau.
    Body : {"target_mac": "XX:XX:XX:XX:XX:XX", "renew_dhcp": true, "test_internet": true}
    """
    data = request.get_json(silent=True) or {}
    target_mac = data.get('target_mac')

    if not target_mac:
        return jsonify({'error': 'target_mac requis'}), 400

    renew_dhcp = data.get('renew_dhcp', True)
    test_internet = data.get('test_internet', True)

    if _events:
        _events.log('info', f'MAC spoofing vers {target_mac}...')

    # Lancer le spoofing dans un thread pour ne pas bloquer la réponse HTTP
    # Les événements WebSocket informent le frontend de la progression
    def run_spoof():
        try:
            _mac_spoofer.spoof(
                target_mac,
                renew_dhcp=renew_dhcp,
                test_internet=test_internet,
            )
        except Exception as e:
            if _events:
                _events.log('error', f'Erreur spoofing: {e}')

    thread = threading.Thread(target=run_spoof, daemon=True)
    thread.start()

    return jsonify({'status': 'started', 'target_mac': target_mac})


@portal_bp.route('/portal/mac/restore', methods=['POST'])
def restore_mac():
    """Restaure la MAC originale."""
    if _events:
        _events.log('info', 'Restauration de la MAC originale...')

    try:
        result = _mac_spoofer.restore()
        return jsonify(result)
    except Exception as e:
        if _events:
            _events.log('error', f'Erreur restauration MAC : {e}')
        return jsonify({'success': False, 'error': str(e)}), 500


# --- Audit ---

@portal_bp.route('/portal/audit', methods=['GET'])
def audit_portal():
    """
    Lance un audit de sécurité complet du portail captif.
    Utilise le dernier résultat de détection si disponible.
    """
    if _events:
        _events.log('info', 'Audit de sécurité du portail captif...')

    try:
        portal_ip = None
        portal_port = None

        if _last_detect_result:
            portal_ip = _last_detect_result.get('portal_ip')
            portal_port = _last_detect_result.get('portal_port')

        # Override depuis les paramètres GET
        if request.args.get('ip'):
            portal_ip = request.args.get('ip')
        if request.args.get('port'):
            portal_port = int(request.args.get('port'))

        result = _auditor.audit(
            portal_ip=portal_ip,
            portal_port=portal_port,
            detect_result=_last_detect_result,
        )

        return jsonify(result)

    except Exception as e:
        if _events:
            _events.log('error', f'Erreur audit portail : {e}')
        return jsonify({'error': str(e)}), 500
