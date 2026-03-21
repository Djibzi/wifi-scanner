# Proxy vers modules/host_discovery.py à la racine du projet
import importlib.util, os, sys
if getattr(sys, 'frozen', False):
    _src = os.path.join(sys._MEIPASS, 'modules', 'host_discovery.py')
else:
    _src = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'modules', 'host_discovery.py'))
_spec = importlib.util.spec_from_file_location('_root_host_discovery', _src)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
globals().update({k: v for k, v in vars(_mod).items() if not k.startswith('_')})
