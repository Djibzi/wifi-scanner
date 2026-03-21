# Proxy vers core/models.py à la racine du projet
# Compatible PyInstaller (mode frozen)
import importlib.util, os, sys
if getattr(sys, 'frozen', False):
    _src = os.path.join(sys._MEIPASS, 'core', 'models.py')
else:
    _src = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'core', 'models.py'))
_spec = importlib.util.spec_from_file_location('_root_models', _src)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
globals().update({k: v for k, v in vars(_mod).items() if not k.startswith('_')})
Severity = _mod.Severity
Host = _mod.Host
Port = _mod.Port
Vulnerability = _mod.Vulnerability
WifiInfo = _mod.WifiInfo
WifiVulnerability = _mod.WifiVulnerability
ScanResult = _mod.ScanResult
Protocol = _mod.Protocol
PortState = _mod.PortState
ScanMode = _mod.ScanMode
