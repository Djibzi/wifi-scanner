# radar_engine.py — Moteur de ping radar pour la surveillance continue
# Calcule la position des appareils sur le radar via latence et type

import subprocess
import threading
import time
import math
import platform


# Secteurs angulaires par type d'appareil (en degrés)
DEVICE_TYPE_SECTORS = {
    'router': (0, 30),
    'gateway': (0, 30),
    'server': (30, 70),
    'desktop': (70, 120),
    'pc': (70, 120),
    'laptop': (120, 170),
    'notebook': (120, 170),
    'phone': (170, 220),
    'mobile': (170, 220),
    'tablet': (220, 260),
    'printer': (260, 300),
    'iot': (300, 340),
    'camera': (300, 340),
    'unknown': (340, 360),
}

# Nombre max d'échantillons de latence pour le lissage
LATENCY_HISTORY_SIZE = 5

# Nombre de ratés avant de considérer l'appareil hors ligne
MAX_MISSES = 3

# Rayon max du radar (en unités arbitraires)
RADAR_RADIUS_MAX = 100.0

# Latence de référence pour la conversion logarithmique (ms)
LATENCY_REF_MS = 500.0


class RadarDevice:
    # Représente un appareil suivi par le radar

    def __init__(self, ip, mac='', hostname='', device_type='unknown'):
        self.ip = ip
        self.mac = mac
        self.hostname = hostname
        self.device_type = device_type.lower() if device_type else 'unknown'
        self.latency_history = []
        self.smoothed_latency = 0.0
        self.radius = RADAR_RADIUS_MAX
        self.angle = 0.0
        self.x = 0.0
        self.y = 0.0
        self.online = False
        self.miss_count = 0
        self.last_seen = 0.0

    def to_dict(self):
        # Sérialise l'appareil pour l'API et les événements
        return {
            'ip': self.ip,
            'mac': self.mac,
            'hostname': self.hostname,
            'device_type': self.device_type,
            'latency': round(self.smoothed_latency, 2),
            'radius': round(self.radius, 2),
            'angle': round(self.angle, 2),
            'x': round(self.x, 2),
            'y': round(self.y, 2),
            'online': self.online,
            'last_seen': self.last_seen,
        }


class RadarEngine:
    # Moteur principal du radar — pings continus et calcul de positions

    def __init__(self, events=None):
        self._events = events
        self._devices = {}
        self._running = False
        self._thread = None
        self._lock = threading.Lock()
        self._ping_interval = 2.0
        self._angle_counters = {}

    def start(self):
        # Démarre la boucle de ping en arrière-plan
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._ping_loop, daemon=True)
        self._thread.start()
        if self._events:
            self._events.emit('radar:started', {})
            self._events.log('info', 'Radar démarré')

    def stop(self):
        # Arrête la boucle de ping
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        if self._events:
            self._events.emit('radar:stopped', {})
            self._events.log('info', 'Radar arrêté')

    def is_running(self):
        return self._running

    def add_device(self, ip, mac='', hostname='', device_type='unknown'):
        # Ajoute un appareil au radar ou met à jour ses infos
        with self._lock:
            if ip in self._devices:
                # Mettre à jour les infos si fournies
                dev = self._devices[ip]
                if mac:
                    dev.mac = mac
                if hostname:
                    dev.hostname = hostname
                if device_type and device_type != 'unknown':
                    dev.device_type = device_type.lower()
                    dev.angle = self._assign_angle(dev.device_type)
                return dev

            device = RadarDevice(ip, mac, hostname, device_type)
            device.angle = self._assign_angle(device.device_type)
            self._devices[ip] = device

        if self._events:
            self._events.emit('radar:device_added', device.to_dict())

        return device

    def remove_device(self, ip):
        # Retire un appareil du radar
        with self._lock:
            if ip in self._devices:
                del self._devices[ip]

    def get_devices(self):
        # Retourne la liste de tous les appareils
        with self._lock:
            return [dev.to_dict() for dev in self._devices.values()]

    def get_device(self, ip):
        # Retourne un appareil spécifique
        with self._lock:
            dev = self._devices.get(ip)
            return dev.to_dict() if dev else None

    def ping_device(self, ip):
        # Ping un seul appareil et retourne le résultat
        latency = self._subprocess_ping(ip)
        with self._lock:
            if ip in self._devices:
                self._update_device(self._devices[ip], latency)
                return self._devices[ip].to_dict()
        # Appareil inconnu — l'ajouter automatiquement
        device = self.add_device(ip)
        with self._lock:
            self._update_device(device, latency)
            return device.to_dict()

    def _ping_loop(self):
        # Boucle principale — ping tous les appareils à chaque cycle
        while self._running:
            with self._lock:
                ips = list(self._devices.keys())

            if not ips:
                time.sleep(self._ping_interval)
                continue

            # Ping chaque appareil en parallèle
            threads = []
            results = {}

            for ip in ips:
                t = threading.Thread(
                    target=self._ping_worker,
                    args=(ip, results),
                    daemon=True,
                )
                threads.append(t)
                t.start()

            # Attendre la fin de tous les pings
            for t in threads:
                t.join(timeout=5)

            # Mettre à jour les appareils
            updated = []
            with self._lock:
                for ip, latency in results.items():
                    if ip in self._devices:
                        self._update_device(self._devices[ip], latency)
                        updated.append(self._devices[ip].to_dict())

            # Émettre la mise à jour complète
            if self._events and updated:
                self._events.emit('radar:update', {'devices': updated})

            time.sleep(self._ping_interval)

    def _ping_worker(self, ip, results):
        # Worker de ping pour exécution parallèle
        results[ip] = self._subprocess_ping(ip)

    def _subprocess_ping(self, ip):
        # Exécute un ping système et retourne la latence en ms (ou -1 si échec)
        try:
            if platform.system() == 'Windows':
                cmd = ['ping', '-n', '1', '-w', '1000', ip]
            else:
                cmd = ['ping', '-c', '1', '-W', '1', ip]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3,
            )

            if result.returncode == 0:
                output = result.stdout
                # Extraire la latence depuis la sortie
                latency = self._parse_ping_output(output)
                return latency

            return -1.0

        except (subprocess.TimeoutExpired, Exception):
            return -1.0

    def _parse_ping_output(self, output):
        # Parse la sortie du ping pour extraire la latence
        # Windows : "temps=3ms" ou "time=3ms" ou "temps<1ms"
        # Linux : "time=3.14 ms"
        import re
        patterns = [
            r'time[=<](\d+\.?\d*)\s*ms',
            r'temps[=<](\d+\.?\d*)\s*ms',
            r'zeit[=<](\d+\.?\d*)\s*ms',
        ]
        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return float(match.group(1))
        return -1.0

    def _update_device(self, device, latency):
        # Met à jour un appareil avec la nouvelle latence
        if latency >= 0:
            # Appareil en ligne
            device.miss_count = 0
            device.online = True
            device.last_seen = time.time()

            # Historique de latence pour lissage
            device.latency_history.append(latency)
            if len(device.latency_history) > LATENCY_HISTORY_SIZE:
                device.latency_history = device.latency_history[-LATENCY_HISTORY_SIZE:]

            # Latence lissée (moyenne des derniers échantillons)
            device.smoothed_latency = (
                sum(device.latency_history) / len(device.latency_history)
            )

            # Conversion latence -> rayon (échelle logarithmique)
            device.radius = self._latency_to_radius(device.smoothed_latency)

        else:
            # Ping raté
            device.miss_count += 1
            if device.miss_count >= MAX_MISSES:
                device.online = False

        # Calculer les coordonnées x, y
        angle_rad = math.radians(device.angle)
        device.x = device.radius * math.cos(angle_rad)
        device.y = device.radius * math.sin(angle_rad)

    def _latency_to_radius(self, latency_ms):
        # Convertit une latence en rayon sur le radar (échelle logarithmique)
        # Latence faible = proche du centre, latence élevée = loin
        if latency_ms <= 0:
            return RADAR_RADIUS_MAX

        # Échelle log : 1ms -> ~10, 10ms -> ~40, 100ms -> ~70, 500ms -> ~100
        normalized = math.log10(1 + latency_ms) / math.log10(1 + LATENCY_REF_MS)
        radius = min(normalized * RADAR_RADIUS_MAX, RADAR_RADIUS_MAX)
        return max(radius, 5.0)

    def _assign_angle(self, device_type):
        # Assigne un angle au device selon son type (secteur)
        dtype = device_type.lower() if device_type else 'unknown'

        # Trouver le secteur correspondant
        sector = DEVICE_TYPE_SECTORS.get(dtype, DEVICE_TYPE_SECTORS['unknown'])
        start, end = sector

        # Compteur pour espacer les appareils du même type
        if dtype not in self._angle_counters:
            self._angle_counters[dtype] = 0
        self._angle_counters[dtype] += 1
        count = self._angle_counters[dtype]

        # Répartir dans le secteur
        span = end - start
        if span <= 0:
            span = 20
        offset = (count * 15) % span
        angle = start + offset

        return angle % 360
