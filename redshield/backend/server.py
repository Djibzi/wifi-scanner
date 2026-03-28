# server.py — Serveur Flask + Socket.IO pour REDSHIELD
# Point d'entrée du backend Python

import os
import sys
import argparse
import threading
import time
import webbrowser
from datetime import datetime

# Chemins critiques
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BACKEND_DIR, '..', '..'))

# BACKEND_DIR doit être en premier pour résoudre core/events.py, core/database.py
# PROJECT_ROOT est utilisé par les proxy pour charger les modules racine
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)
# Forcer BACKEND_DIR en position 0
if BACKEND_DIR in sys.path:
    sys.path.remove(BACKEND_DIR)
sys.path.insert(0, BACKEND_DIR)

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO

# Imports depuis la racine du projet (core/ et modules/)
from core.config import ScannerConfig
from core.logger import ScannerLogger
from core.models import ScanResult

# Imports spécifiques au backend redshield
from core.events import events
from core.database import Database

# Routes API
from api.routes_scan import scan_bp, init_scan_routes
from api.routes_hosts import hosts_bp
from api.routes_vulns import vulns_bp
from api.routes_traffic import traffic_bp, init_traffic_routes
from api.routes_report import report_bp
from api.routes_settings import settings_bp, init_settings_routes
from api.routes_wifi import wifi_bp
from api.routes_radar import radar_bp, init_radar_routes
from api.routes_portal import portal_bp, init_portal_routes
from modules.radar_engine import RadarEngine


# --- Création de l'app Flask ---

if getattr(sys, 'frozen', False):
    FRONTEND_DIR = os.path.join(sys._MEIPASS, 'frontend')
else:
    FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'frontend'))
app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path='')
app.config['SECRET_KEY'] = os.environ.get('REDSHIELD_SECRET', 'dev-placeholder-key')
CORS(app)

socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading')
events.set_socketio(socketio)

# --- Base de données ---
db = Database()

# --- État global du scan ---
scan_state = {
    'running': False,
    'result': None,
    'progress': 0,
    'current_module': '',
    'start_time': None,
}


# --- Enregistrement des blueprints ---

app.register_blueprint(scan_bp, url_prefix='/api')
app.register_blueprint(hosts_bp, url_prefix='/api')
app.register_blueprint(vulns_bp, url_prefix='/api')
app.register_blueprint(traffic_bp, url_prefix='/api')
app.register_blueprint(report_bp, url_prefix='/api')
app.register_blueprint(settings_bp, url_prefix='/api')
app.register_blueprint(wifi_bp, url_prefix='/api')
app.register_blueprint(radar_bp, url_prefix='/api')
app.register_blueprint(portal_bp, url_prefix='/api')

# --- Moteur radar ---
radar_engine = RadarEngine(events=events)

# Initialiser les routes qui ont besoin de dépendances
init_scan_routes(scan_state, db, events)
init_traffic_routes(events)
init_settings_routes(db)
init_radar_routes(radar_engine, scan_state, events)
init_portal_routes(events)


# --- Servir le frontend ---

@app.route('/')
def serve_frontend():
    return send_from_directory(FRONTEND_DIR, 'index.html')


# --- Route santé ---

@app.route('/api/health')
def health():
    return jsonify({
        'status': 'ok',
        'version': '1.1.0',
        'name': 'REDSHIELD',
    })


# --- Événements WebSocket ---

@socketio.on('connect')
def handle_connect():
    events.log('info', 'Client connecté')


@socketio.on('disconnect')
def handle_disconnect():
    events.log('info', 'Client déconnecté')


# --- Point d'entrée ---

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='REDSHIELD Backend')
    parser.add_argument('--port', type=int, default=5678, help='Port du serveur')
    parser.add_argument('--debug', action='store_true', help='Mode debug')
    args = parser.parse_args()

    print(f'[REDSHIELD] Serveur démarré sur http://127.0.0.1:{args.port}')
    # Ouvrir dans le navigateur
    webbrowser.open(f'http://127.0.0.1:{args.port}')
    socketio.run(app, host='127.0.0.1', port=args.port, debug=args.debug)
