# Proxy vers core/config.py à la racine du projet
# Compatible PyInstaller (mode frozen)
import importlib.util, os, sys

if getattr(sys, 'frozen', False):
    # Mode bundlé : le fichier est dans _MEIPASS/core/
    _src = os.path.join(sys._MEIPASS, 'core', 'config.py')
else:
    _src = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'core', 'config.py'))

_spec = importlib.util.spec_from_file_location('_root_config', _src)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
globals().update({k: v for k, v in vars(_mod).items() if not k.startswith('_')})
ScannerConfig = _mod.ScannerConfig
