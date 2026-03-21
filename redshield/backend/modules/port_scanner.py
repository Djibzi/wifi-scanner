# Proxy vers modules/port_scanner.py à la racine du projet
import importlib.util, os, sys
if getattr(sys, 'frozen', False):
    _src = os.path.join(sys._MEIPASS, 'modules', 'port_scanner.py')
else:
    _src = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'modules', 'port_scanner.py'))
_spec = importlib.util.spec_from_file_location('_root_port_scanner', _src)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
globals().update({k: v for k, v in vars(_mod).items() if not k.startswith('_')})
