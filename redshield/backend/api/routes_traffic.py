# routes_traffic.py — Routes API pour l'analyse de trafic
# Capture les paquets en temps réel et les envoie au frontend

import threading
import time
import socket
import struct

from flask import Blueprint, jsonify

traffic_bp = Blueprint('traffic', __name__)

_events = None
_running = False
_packets = []        # Liste des derniers paquets capturés
_host_names = {}     # Cache IP -> nom d'hôte
_stats = {
    'packets': 0,
    'bytes': 0,
    'protocols': {},
    'top_talkers': {},
    'arp_anomalies': 0,
    'unencrypted_protocols': [],
}


def init_traffic_routes(events):
    global _events
    _events = events


def _resolve_name(ip):
    # Résout le nom d'un hôte (avec cache)
    if ip in _host_names:
        return _host_names[ip]

    # Chercher dans les hôtes du scan
    from api.routes_scan import _scan_state
    if _scan_state and _scan_state.get('result'):
        for host in (_scan_state['result'].hosts or []):
            if host.ip == ip:
                name = host.hostname or host.device_type or host.vendor or ip
                _host_names[ip] = name
                return name

    # Reverse DNS
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        _host_names[ip] = hostname
        return hostname
    except Exception:
        _host_names[ip] = ip
        return ip


@traffic_bp.route('/traffic/start', methods=['POST'])
def start_traffic():
    global _running, _packets, _stats
    if _running:
        return jsonify({'error': 'Capture déjà en cours'}), 409

    _running = True
    _packets = []
    _stats = {
        'packets': 0,
        'bytes': 0,
        'protocols': {},
        'top_talkers': {},
        'arp_anomalies': 0,
        'unencrypted_protocols': [],
    }

    thread = threading.Thread(target=_capture_loop, daemon=True)
    thread.start()

    return jsonify({'status': 'started'})


@traffic_bp.route('/traffic/stop', methods=['POST'])
def stop_traffic():
    global _running
    _running = False
    return jsonify({'status': 'stopped'})


@traffic_bp.route('/traffic/stats')
def traffic_stats():
    # Stats + top talkers avec noms
    top = sorted(_stats['top_talkers'].items(), key=lambda x: x[1], reverse=True)[:10]
    top_with_names = [[_resolve_name(ip), bytes_count, ip] for ip, bytes_count in top]

    return jsonify({
        'packets': _stats['packets'],
        'bytes': _stats['bytes'],
        'arp_anomalies': _stats['arp_anomalies'],
        'unencrypted_protocols': _stats['unencrypted_protocols'],
        'protocols': _stats['protocols'],
        'top_talkers': top_with_names,
    })


@traffic_bp.route('/traffic/packets')
def get_packets():
    # Retourne les 100 derniers paquets
    return jsonify(_packets[-100:])


@traffic_bp.route('/traffic/packets/<ip>')
def get_packets_by_host(ip):
    # Retourne les paquets filtrés pour un hôte (src ou dst)
    host_packets = [p for p in _packets if p.get('src') == ip or p.get('dst') == ip]
    return jsonify(host_packets[-200:])


# --- Protocoles connus ---

KNOWN_PORTS = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP', 68: 'DHCP', 80: 'HTTP', 110: 'POP3',
    123: 'NTP', 137: 'NetBIOS', 138: 'NetBIOS', 139: 'NetBIOS-SSN',
    143: 'IMAP', 161: 'SNMP', 443: 'HTTPS', 445: 'SMB',
    465: 'SMTPS', 587: 'SMTP', 993: 'IMAPS', 995: 'POP3S',
    1883: 'MQTT', 3389: 'RDP', 5353: 'mDNS', 5900: 'VNC',
    8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 8883: 'MQTTS',
    49152: 'Apple', 62078: 'Apple-Lockdown',
}

UNENCRYPTED = {80, 21, 23, 25, 110, 143, 1883}


def _get_protocol_name(sport, dport):
    # Identifie le protocole à partir des ports
    if dport in KNOWN_PORTS:
        return KNOWN_PORTS[dport]
    if sport in KNOWN_PORTS:
        return KNOWN_PORTS[sport]
    return f'Port {min(sport, dport)}'


def _capture_loop():
    # Boucle de capture — essaye scapy puis raw socket
    global _running

    if _events:
        _events.log('info', 'Démarrage de la capture de trafic...')

    # Essayer avec scapy
    if _capture_with_scapy():
        return

    # Fallback raw socket
    if _capture_with_raw_socket():
        return

    if _events:
        _events.log('warning', 'Impossible de capturer le trafic — '
                    'lancez en tant qu\'administrateur')
    global _running
    _running = False


def _capture_with_scapy():
    # Capture avec scapy (meilleure option)
    global _running
    try:
        from scapy.all import sniff, IP, TCP, UDP, ARP, DNS, DNSQR, conf
        conf.verb = 0
    except ImportError:
        if _events:
            _events.log('warning', 'scapy non installé — tentative raw socket')
        return False

    try:
        def process_packet(pkt):
            if not _running:
                return

            pkt_info = {
                'time': time.time(),
                'size': len(pkt),
            }

            # ARP
            if pkt.haslayer(ARP):
                src_ip = pkt[ARP].psrc
                dst_ip = pkt[ARP].pdst
                pkt_info.update({
                    'src': src_ip,
                    'dst': dst_ip,
                    'protocol': 'ARP',
                    'info': f"Who has {dst_ip}?" if pkt[ARP].op == 1 else f"{src_ip} is at {pkt[ARP].hwsrc}",
                })
                _record_packet(pkt_info)
                return

            if not pkt.haslayer(IP):
                return

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            pkt_info['src'] = src_ip
            pkt_info['dst'] = dst_ip

            # TCP
            if pkt.haslayer(TCP):
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                flags = pkt[TCP].flags
                proto = _get_protocol_name(sport, dport)
                flag_str = str(flags) if flags else ''

                info = f'{sport} → {dport}'
                if 'S' in flag_str and 'A' not in flag_str:
                    info += ' [SYN]'
                elif 'S' in flag_str and 'A' in flag_str:
                    info += ' [SYN-ACK]'
                elif 'F' in flag_str:
                    info += ' [FIN]'
                elif 'R' in flag_str:
                    info += ' [RST]'

                pkt_info.update({
                    'protocol': proto,
                    'sport': sport,
                    'dport': dport,
                    'info': info,
                })

                # Détecter protocoles non chiffrés
                if sport in UNENCRYPTED or dport in UNENCRYPTED:
                    port = sport if sport in UNENCRYPTED else dport
                    proto_name = KNOWN_PORTS.get(port, str(port))
                    if proto_name not in _stats['unencrypted_protocols']:
                        _stats['unencrypted_protocols'].append(proto_name)

            # UDP
            elif pkt.haslayer(UDP):
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                proto = _get_protocol_name(sport, dport)

                info = f'{sport} → {dport}'

                # DNS
                if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                    domain = pkt[DNSQR].qname.decode('utf-8', errors='replace').rstrip('.')
                    proto = 'DNS'
                    info = f'Query: {domain}'

                pkt_info.update({
                    'protocol': proto,
                    'sport': sport,
                    'dport': dport,
                    'info': info,
                })

            else:
                pkt_info.update({
                    'protocol': f'IP({pkt[IP].proto})',
                    'info': '',
                })

            _record_packet(pkt_info)

        if _events:
            _events.log('info', 'Capture avec scapy activée')

        while _running:
            sniff(timeout=2, prn=process_packet, store=False)
            _send_stats()

        return True

    except PermissionError:
        if _events:
            _events.log('warning', 'Droits insuffisants pour scapy')
        return False
    except Exception as e:
        if _events:
            _events.log('error', f'Erreur scapy : {e}')
        return False


def _capture_with_raw_socket():
    # Capture avec raw socket (fallback Windows)
    global _running
    import platform

    try:
        if platform.system() == 'Windows':
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            sock.bind((local_ip, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

        sock.settimeout(1)
        last_send = time.time()

        if _events:
            _events.log('info', 'Capture avec raw socket activée')

        while _running:
            try:
                data = sock.recv(65535)
                if data and len(data) >= 20:
                    _process_raw_packet(data)
            except socket.timeout:
                pass

            # Envoyer les stats toutes les 2 secondes
            if time.time() - last_send >= 2:
                _send_stats()
                last_send = time.time()

        if platform.system() == 'Windows':
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sock.close()
        return True

    except PermissionError:
        if _events:
            _events.log('warning', 'Droits insuffisants pour raw socket')
        return False
    except Exception as e:
        if _events:
            _events.log('error', f'Erreur raw socket : {e}')
        return False


def _process_raw_packet(data):
    # Parse un paquet IP brut
    iph = struct.unpack('!BBHHHBBH4s4s', data[:20])
    protocol = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])
    ihl = (iph[0] & 0xF) * 4

    pkt_info = {
        'time': time.time(),
        'size': len(data),
        'src': src_ip,
        'dst': dst_ip,
    }

    # TCP (6)
    if protocol == 6 and len(data) >= ihl + 4:
        sport, dport = struct.unpack('!HH', data[ihl:ihl + 4])
        proto = _get_protocol_name(sport, dport)
        pkt_info.update({
            'protocol': proto,
            'sport': sport,
            'dport': dport,
            'info': f'{sport} → {dport}',
        })
        if sport in UNENCRYPTED or dport in UNENCRYPTED:
            port = sport if sport in UNENCRYPTED else dport
            name = KNOWN_PORTS.get(port, str(port))
            if name not in _stats['unencrypted_protocols']:
                _stats['unencrypted_protocols'].append(name)

    # UDP (17)
    elif protocol == 17 and len(data) >= ihl + 4:
        sport, dport = struct.unpack('!HH', data[ihl:ihl + 4])
        proto = _get_protocol_name(sport, dport)
        pkt_info.update({
            'protocol': proto,
            'sport': sport,
            'dport': dport,
            'info': f'{sport} → {dport}',
        })

    # ICMP (1)
    elif protocol == 1:
        pkt_info.update({
            'protocol': 'ICMP',
            'info': 'Ping',
        })

    else:
        pkt_info.update({
            'protocol': f'IP({protocol})',
            'info': '',
        })

    _record_packet(pkt_info)


def _record_packet(pkt_info):
    # Enregistre un paquet et met à jour les stats
    global _packets, _stats

    # Résoudre les noms
    src_name = _resolve_name(pkt_info.get('src', ''))
    dst_name = _resolve_name(pkt_info.get('dst', ''))
    pkt_info['src_name'] = src_name
    pkt_info['dst_name'] = dst_name

    # Garder les 500 derniers paquets
    _packets.append(pkt_info)
    if len(_packets) > 500:
        _packets = _packets[-500:]

    # Stats
    _stats['packets'] += 1
    _stats['bytes'] += pkt_info.get('size', 0)

    proto = pkt_info.get('protocol', 'Autre')
    _stats['protocols'][proto] = _stats['protocols'].get(proto, 0) + 1

    src = pkt_info.get('src', '')
    if src:
        _stats['top_talkers'][src] = _stats['top_talkers'].get(src, 0) + pkt_info.get('size', 0)

    # Envoyer le paquet au frontend en temps réel
    if _events:
        _events.traffic_packet({
            'src': pkt_info.get('src', ''),
            'dst': pkt_info.get('dst', ''),
            'src_name': src_name,
            'dst_name': dst_name,
            'protocol': proto,
            'size': pkt_info.get('size', 0),
            'info': pkt_info.get('info', ''),
        })


def _send_stats():
    # Envoie les stats agrégées au frontend
    if not _events:
        return

    top = sorted(_stats['top_talkers'].items(), key=lambda x: x[1], reverse=True)[:10]
    top_with_names = [[_resolve_name(ip), bytes_count, ip] for ip, bytes_count in top]

    _events.traffic_stats({
        'packets': _stats['packets'],
        'bytes': _stats['bytes'],
        'arp_anomalies': _stats['arp_anomalies'],
        'unencrypted_protocols': _stats['unencrypted_protocols'],
        'protocols': _stats['protocols'],
        'top_talkers': top_with_names,
    })
