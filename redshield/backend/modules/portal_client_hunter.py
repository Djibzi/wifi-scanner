# portal_client_hunter.py — Identification des clients autorisés par le portail
# Analyse le trafic réseau pour distinguer les appareils autorisés (trafic vers Internet)
# des appareils bloqués (pas de trafic sortant)

import ipaddress
import socket
import threading
import time

# IPs publiques routable = trafic Internet réel
_PRIVATE_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('224.0.0.0/4'),
    ipaddress.ip_network('255.255.255.255/32'),
]


def _is_public_ip(ip_str):
    """Retourne True si l'IP est publique (routée vers Internet)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return not any(ip in net for net in _PRIVATE_RANGES)
    except ValueError:
        return False


def _get_own_ips():
    """Retourne toutes les IPs locales de la machine."""
    ips = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            ips.add(info[4][0])
    except Exception:
        pass
    # Ajouter localhost
    ips.add('127.0.0.1')
    return ips


class PortalClientHunter:
    """
    Identifie les clients autorisés par le portail captif en écoutant le trafic.

    Méthode :
    1. Écoute passive avec Scapy
    2. Pour chaque paquet, vérifie si la destination est une IP publique
    3. Les appareils qui envoient du trafic vers Internet = autorisés
    4. Score de confiance basé sur : nombre de paquets, diversité destinations, durée
    5. Résolution DNS inversée des destinations

    Résultat : liste de clients avec status 'authorized', 'blocked' ou 'infrastructure'
    """

    def __init__(self, events=None):
        self.events = events
        self._running = False
        self._clients = {}   # mac -> {ip, mac, vendor, packets_ext, destinations, first_seen, last_seen}
        self._own_ips = _get_own_ips()
        self._own_mac = None
        self._gateway_ip = None
        self._gateway_mac = None
        self._dns_cache = {}
        self._thread = None

    def start(self, duration=30):
        """Démarre l'écoute du trafic en arrière-plan."""
        if self._running:
            return
        self._running = True
        self._clients = {}
        self._gateway_ip = self._detect_gateway()
        self._own_mac = self._get_own_mac()
        self._thread = threading.Thread(
            target=self._capture_loop,
            args=(duration,),
            daemon=True,
        )
        self._thread.start()

    def stop(self):
        """Arrête l'écoute."""
        self._running = False

    def get_clients(self):
        """Retourne la liste des clients avec leur statut."""
        result = []
        now = time.time()

        for mac, data in self._clients.items():
            packets_ext = data.get('packets_ext', 0)
            duration_seen = now - data.get('first_seen', now)

            # Calcul du score de confiance (0.0 → 1.0)
            confidence = self._compute_confidence(
                packets_ext,
                len(data.get('destinations', set())),
                duration_seen,
            )

            # Statut
            if data.get('is_gateway'):
                status = 'infrastructure'
            elif data.get('is_self'):
                status = 'blocked'  # Soi-même = bloqué par le portail
            elif packets_ext >= 5:
                status = 'authorized'
            else:
                status = 'blocked'

            client = {
                'ip': data.get('ip', ''),
                'mac': mac,
                'vendor': data.get('vendor', ''),
                'status': status,
                'traffic_count': packets_ext,
                'destinations': list(data.get('destinations', set()))[:5],
                'confidence': round(confidence, 2),
                'is_self': data.get('is_self', False),
                'is_gateway': data.get('is_gateway', False),
            }
            result.append(client)

        # Trier : infrastructure d'abord, puis autorisés, puis bloqués
        order = {'infrastructure': 0, 'authorized': 1, 'blocked': 2}
        result.sort(key=lambda c: (order.get(c['status'], 3), -c['traffic_count']))
        return result

    def _compute_confidence(self, packets, dest_count, duration_s):
        """Calcule un score de confiance 0-1 pour un client autorisé."""
        score = 0.0
        # Paquets vers Internet
        if packets >= 5:
            score += min(packets / 100, 0.5)
        # Diversité des destinations
        if dest_count >= 2:
            score += min(dest_count / 10, 0.3)
        # Durée d'observation
        if duration_s >= 10:
            score += min(duration_s / 60, 0.2)
        return min(score, 1.0)

    def _capture_loop(self, duration):
        """Boucle principale de capture de paquets."""
        if self.events:
            self.events.log('info', f'Écoute du trafic portail ({duration}s)...')

        # Essayer avec Scapy
        if self._capture_with_scapy(duration):
            return

        # Fallback ARP scan
        self._fallback_arp(duration)

    def _capture_with_scapy(self, duration):
        """Capture avec Scapy (meilleure option, nécessite Npcap sous Windows)."""
        try:
            from scapy.all import sniff, IP, ARP, Ether, conf
            conf.verb = 0
        except ImportError:
            if self.events:
                self.events.log('warning', 'Scapy non disponible pour la chasse aux clients')
            return False

        start_time = time.time()
        last_emit = 0

        def process_packet(pkt):
            nonlocal last_emit
            if not self._running:
                return

            # Traiter les paquets Ethernet
            if pkt.haslayer(Ether):
                src_mac = pkt[Ether].src.upper()
                dst_mac = pkt[Ether].dst.upper()

                # Mettre à jour l'entrée MAC dans le cache
                if src_mac and src_mac not in ('FF:FF:FF:FF:FF:FF',):
                    ip_src = None
                    if pkt.haslayer(IP):
                        ip_src = pkt[IP].src

                    if src_mac not in self._clients:
                        self._clients[src_mac] = {
                            'mac': src_mac,
                            'ip': ip_src or '',
                            'vendor': self._get_vendor(src_mac),
                            'packets_ext': 0,
                            'destinations': set(),
                            'first_seen': time.time(),
                            'last_seen': time.time(),
                            'is_self': ip_src in self._own_ips if ip_src else False,
                            'is_gateway': ip_src == self._gateway_ip if ip_src else False,
                        }
                    else:
                        if ip_src:
                            self._clients[src_mac]['ip'] = ip_src
                        self._clients[src_mac]['last_seen'] = time.time()

                    # Trafic vers Internet
                    if pkt.haslayer(IP):
                        dst_ip = pkt[IP].dst
                        if _is_public_ip(dst_ip) and src_mac in self._clients:
                            self._clients[src_mac]['packets_ext'] += 1
                            # Résoudre le domaine destination
                            domain = self._resolve_domain(dst_ip)
                            if domain:
                                self._clients[src_mac]['destinations'].add(domain)

            # Émettre les mises à jour toutes les 10s
            now = time.time()
            if now - last_emit >= 10 and self.events:
                self._emit_update()
                last_emit = now

        try:
            end_time = time.time() + duration
            while self._running and time.time() < end_time:
                remaining = end_time - time.time()
                if remaining <= 0:
                    break
                sniff(timeout=min(2, remaining), prn=process_packet, store=False)

            # Émettre la mise à jour finale
            if self.events:
                self._emit_update()

            self._running = False
            return True

        except PermissionError:
            if self.events:
                self.events.log('warning', 'Droits insuffisants pour la capture (lancez en admin)')
            return False
        except Exception as e:
            if self.events:
                self.events.log('error', f'Erreur capture portail: {e}')
            return False

    def _fallback_arp(self, duration):
        """Fallback : scan ARP simple pour lister les appareils (sans analyse trafic)."""
        try:
            from scapy.all import ARP, Ether, srp, conf
            conf.verb = 0

            gateway_ip = self._gateway_ip or '192.168.1.1'
            # Déduire le sous-réseau depuis la gateway
            parts = gateway_ip.split('.')
            subnet = f'{".".join(parts[:3])}.0/24'

            arp_req = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=subnet)
            answered, _ = srp(arp_req, timeout=2, verbose=0)

            for sent, received in answered:
                mac = received[ARP].hwsrc.upper()
                ip = received[ARP].psrc

                if mac not in self._clients:
                    self._clients[mac] = {
                        'mac': mac,
                        'ip': ip,
                        'vendor': self._get_vendor(mac),
                        'packets_ext': 0,
                        'destinations': set(),
                        'first_seen': time.time(),
                        'last_seen': time.time(),
                        'is_self': ip in self._own_ips,
                        'is_gateway': ip == gateway_ip,
                    }

            if self.events:
                self._emit_update()

        except Exception as e:
            if self.events:
                self.events.log('error', f'Erreur ARP fallback: {e}')

        self._running = False

    def _emit_update(self):
        """Émet un événement WebSocket avec la liste des clients."""
        clients = self.get_clients()
        summary = [
            {
                'mac': c['mac'],
                'traffic_count': c['traffic_count'],
                'status': c['status'],
            }
            for c in clients
        ]
        if self.events:
            self.events.emit('portal:clients_update', {'clients': summary})

    def _detect_gateway(self):
        """Détecte l'IP de la gateway."""
        try:
            import subprocess
            result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=5)
            import re
            for line in result.stdout.splitlines():
                if 'Passerelle' in line or 'Gateway' in line:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        return match.group(1)
        except Exception:
            pass
        return None

    def _get_own_mac(self):
        """Retourne la MAC de la carte réseau principale."""
        try:
            import uuid
            mac_int = uuid.getnode()
            mac_hex = f'{mac_int:012X}'
            return ':'.join(mac_hex[i:i+2] for i in range(0, 12, 2))
        except Exception:
            return None

    def _get_vendor(self, mac):
        """Retourne le fabricant à partir des 3 premiers octets de la MAC."""
        oui = mac.replace(':', '').replace('-', '').upper()[:6]
        # OUI connus courants
        oui_db = {
            '080027': 'Oracle/VirtualBox',
            '000C29': 'VMware',
            '005056': 'VMware',
            '00163E': 'Xen',
            'B827EB': 'Raspberry Pi',
            'DC0EA1': 'Raspberry Pi',
            'E45F01': 'Raspberry Pi',
            '001A2B': 'Cisco',
            '001B17': 'Cisco',
            'F8D111': 'Apple',
            '3C15C2': 'Apple',
            'A4C361': 'Apple',
            '00236C': 'Apple',
            '040CCE': 'Apple',
            '38F23E': 'Samsung',
            '788CB5': 'Samsung',
            'E8039A': 'Samsung',
        }
        return oui_db.get(oui[:6], '')

    def _resolve_domain(self, ip):
        """Résolution DNS inverse avec cache."""
        if ip in self._dns_cache:
            return self._dns_cache[ip]

        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            # Garder seulement les 2 derniers niveaux du domaine
            parts = hostname.split('.')
            domain = '.'.join(parts[-2:]) if len(parts) >= 2 else hostname
            self._dns_cache[ip] = domain
            return domain
        except Exception:
            self._dns_cache[ip] = ip
            return ip
