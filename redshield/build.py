# build.py — Script de build pour créer l'exécutable REDSHIELD
# Lance PyInstaller avec la bonne configuration

import os
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, '..'))


def build():
    print('[BUILD] Construction de REDSHIELD.exe...')

    # Chemins
    entry = os.path.join(BASE_DIR, 'redshield.py')
    icon = os.path.join(BASE_DIR, 'redshield.ico')
    frontend = os.path.join(BASE_DIR, 'frontend')
    backend = os.path.join(BASE_DIR, 'backend')
    core_dir = os.path.join(PROJECT_ROOT, 'core')
    modules_dir = os.path.join(PROJECT_ROOT, 'modules')
    vuln_db_dir = os.path.join(PROJECT_ROOT, 'vuln_db')

    cmd = [
        sys.executable, '-m', 'PyInstaller',
        '--name=REDSHIELD',
        '--onefile',
        '--console',
        f'--icon={icon}',

        # Inclure le frontend (HTML/CSS/JS)
        f'--add-data={frontend};frontend',

        # Inclure le backend (modules, API, core)
        f'--add-data={backend};backend',

        # Inclure les modules racine
        f'--add-data={core_dir};core',
        f'--add-data={modules_dir};modules',
        f'--add-data={vuln_db_dir};vuln_db',

        # Hidden imports (modules chargés dynamiquement)
        '--hidden-import=flask',
        '--hidden-import=flask_cors',
        '--hidden-import=flask_socketio',
        '--hidden-import=engineio.async_drivers.threading',
        '--hidden-import=webview',
        '--hidden-import=clr_loader',
        '--hidden-import=pythonnet',
        '--hidden-import=scapy',
        '--hidden-import=jinja2',

        # Options
        '--noconfirm',
        '--clean',

        entry,
    ]

    print(f'[BUILD] Commande : {" ".join(cmd[-5:])}...')
    result = subprocess.run(cmd, cwd=BASE_DIR)

    if result.returncode == 0:
        exe_path = os.path.join(BASE_DIR, 'dist', 'REDSHIELD.exe')
        print(f'[BUILD] Succès ! Exécutable : {exe_path}')
        print(f'[BUILD] Taille : {os.path.getsize(exe_path) / 1024 / 1024:.1f} Mo')
    else:
        print('[BUILD] Erreur lors du build')
        sys.exit(1)


if __name__ == '__main__':
    build()
