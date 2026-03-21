# redshield.py — Lanceur desktop REDSHIELD (pywebview + Flask)
# Ouvre l'application dans une fenêtre native Windows

import sys
import os
import threading
import time

# Cacher la console Windows en mode frozen (remplace --windowed qui bloque pywebview)
if getattr(sys, 'frozen', False) and sys.platform == 'win32':
    import ctypes
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

# Détecter si on tourne en mode bundlé (PyInstaller)
if getattr(sys, 'frozen', False):
    BASE_DIR = sys._MEIPASS
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Ajouter les chemins au path
BACKEND_DIR = os.path.join(BASE_DIR, 'backend')
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, '..'))

if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

import webview
from server import app, socketio

PORT = 5678


class RedshieldApp:
    # Application desktop REDSHIELD

    def __init__(self):
        self.server_thread = None
        self.window = None

    def start_server(self):
        # Lance Flask dans un thread séparé
        self.server_thread = threading.Thread(
            target=lambda: socketio.run(
                app,
                host='127.0.0.1',
                port=PORT,
                debug=False,
                use_reloader=False,
                log_output=False,
            ),
            daemon=True,
        )
        self.server_thread.start()

        # Attendre que le serveur soit prêt
        import urllib.request
        for _ in range(30):
            try:
                urllib.request.urlopen(f'http://127.0.0.1:{PORT}/api/health')
                return True
            except Exception:
                time.sleep(0.3)
        return False

    def run(self):
        # Démarrer le serveur Flask
        print('[REDSHIELD] Démarrage du serveur...')
        if not self.start_server():
            print('[REDSHIELD] Erreur : le serveur ne répond pas')
            sys.exit(1)

        print(f'[REDSHIELD] Serveur prêt sur le port {PORT}')

        # Ouvrir la fenêtre native
        self.window = webview.create_window(
            title='REDSHIELD',
            url=f'http://127.0.0.1:{PORT}',
            width=1400,
            height=900,
            min_size=(1000, 700),
            background_color='#0d0b0e',
            text_select=True,
        )

        # Démarrer pywebview (bloquant)
        webview.start(debug=False)


if __name__ == '__main__':
    app_instance = RedshieldApp()
    app_instance.run()
