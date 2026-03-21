# Proxy vers modules/dns_analyzer.py à la racine du projet
import importlib.util, os, sys
if getattr(sys, 'frozen', False):
    _src = os.path.join(sys._MEIPASS, 'modules', 'dns_analyzer.py')
else:
    _src = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'modules', 'dns_analyzer.py'))
_spec = importlib.util.spec_from_file_location('_root_dns_analyzer', _src)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
globals().update({k: v for k, v in vars(_mod).items() if not k.startswith('_')})
