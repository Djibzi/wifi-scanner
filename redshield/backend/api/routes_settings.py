# routes_settings.py — Routes API pour la configuration

from flask import Blueprint, jsonify, request

settings_bp = Blueprint('settings', __name__)

_db = None

# Valeurs par défaut
DEFAULT_SETTINGS = {
    'scan_mode': 'quick',
    'timeout': 0.5,
    'threads': 200,
    'custom_ports': '',
    'max_credential_attempts': 3,
    'theme': 'dark',
    'language': 'fr',
    'notifications': True,
    'promiscuous_mode': False,
}


def init_settings_routes(db):
    global _db
    _db = db


@settings_bp.route('/settings')
def get_settings():
    settings = dict(DEFAULT_SETTINGS)
    if _db:
        for key in DEFAULT_SETTINGS:
            val = _db.get_setting(key)
            if val is not None:
                settings[key] = val
    return jsonify(settings)


@settings_bp.route('/settings', methods=['PUT'])
def update_settings():
    data = request.get_json() or {}
    if not _db:
        return jsonify({'error': 'Base de données non initialisée'}), 500

    for key, value in data.items():
        if key in DEFAULT_SETTINGS:
            _db.set_setting(key, value)

    return jsonify({'status': 'ok'})


@settings_bp.route('/history')
def get_history():
    if not _db:
        return jsonify([])
    return jsonify(_db.get_history())
