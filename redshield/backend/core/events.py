# events.py — Gestionnaire d'événements WebSocket
# Émet les événements temps réel vers le frontend via Socket.IO


class EventEmitter:
    # Centralise l'émission d'événements WebSocket

    def __init__(self, socketio=None):
        self.socketio = socketio

    def set_socketio(self, socketio):
        self.socketio = socketio

    def emit(self, event, data=None):
        # Émet un événement WebSocket
        if self.socketio:
            self.socketio.emit(event, data or {})

    # --- Événements de scan ---

    def scan_started(self, mode, target):
        self.emit('scan:started', {'mode': mode, 'target': target})

    def scan_progress(self, module, percent, message=''):
        self.emit('scan:progress', {
            'module': module,
            'percent': percent,
            'message': message,
        })

    def scan_module_complete(self, module, duration):
        self.emit('scan:module_complete', {
            'module': module,
            'duration': duration,
        })

    def scan_finished(self, score, grade, duration):
        self.emit('scan:finished', {
            'score': score,
            'grade': grade,
            'duration': duration,
        })

    # --- Événements de découverte ---

    def host_found(self, host_data):
        self.emit('host:found', host_data)

    def port_found(self, ip, port, service=''):
        self.emit('port:found', {
            'ip': ip,
            'port': port,
            'service': service,
        })

    def vuln_found(self, vuln_data):
        self.emit('vuln:found', vuln_data)

    # --- Événements de trafic ---

    def traffic_stats(self, stats):
        self.emit('traffic:stats', stats)

    def traffic_packet(self, packet_data):
        self.emit('traffic:packet', packet_data)

    def traffic_alert(self, alert_data):
        self.emit('traffic:alert', alert_data)

    # --- Événements Portail Captif ---

    def portal_detected(self, portal_type, portal_ip, status):
        self.emit('portal:detected', {
            'type': portal_type,
            'portal_ip': portal_ip,
            'status': status,
        })

    def portal_client_found(self, ip, mac, status, traffic_count):
        self.emit('portal:client_found', {
            'ip': ip,
            'mac': mac,
            'status': status,
            'traffic_count': traffic_count,
        })

    def portal_spoof_progress(self, step, success, message):
        self.emit('portal:spoof_progress', {
            'step': step,
            'success': success,
            'message': message,
        })

    def portal_spoof_result(self, success, internet_access=False, new_mac=None, new_ip=None, error=None):
        self.emit('portal:spoof_result', {
            'success': success,
            'internet_access': internet_access,
            'new_mac': new_mac,
            'new_ip': new_ip,
            'error': error,
        })

    def portal_clients_update(self, clients):
        self.emit('portal:clients_update', {'clients': clients})

    # --- Logs terminal ---

    def log(self, level, message):
        self.emit('log:entry', {
            'level': level,
            'message': message,
        })


# Singleton global
events = EventEmitter()
