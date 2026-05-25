"""
DefroxPot Real-Time Streaming Server
=====================================
Standalone Socket.IO server that runs alongside the Django app.
Provides real-time honeypot log streaming and ICMP packet sniffing.

Usage:
    python realtime_server.py              (normal mode — log watcher only)
    sudo python realtime_server.py --sniff (enable raw ICMP packet sniffer)

The server runs on port 9000 and communicates with the frontend via Socket.IO.
"""

import os
import sys
import json
import time
import random
import signal
import logging
import argparse
import threading
from datetime import datetime, timezone
from pathlib import Path

# ============================================================
# Dependencies
# ============================================================
try:
    import socketio
    import eventlet
    import eventlet.wsgi
except ImportError:
    print("\n[!] Missing dependencies. Install them with:")
    print("    pip install python-socketio eventlet\n")
    sys.exit(1)

# Optional: Scapy for ICMP sniffing (requires root/admin)
SCAPY_AVAILABLE = False
try:
    from scapy.all import sniff as scapy_sniff, ICMP, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    pass

# ============================================================
# Configuration
# ============================================================
SOCKETIO_PORT = 9000
CORS_ORIGINS = '*'  # Allow all origins (restrict in production)

# Honeypot log file paths (relative to project root)
BASE_DIR = Path(__file__).resolve().parent
LOG_PATHS = {
    'web': BASE_DIR / 'honeypot' / 'Honeypot_Project_final' / 'var' / 'web_honeypot.log',
    'net': BASE_DIR / 'honeypot' / 'Honeypot_Project_final' / 'var' / 'net_honeypot.log',
    'key': BASE_DIR / 'honeypot' / 'Honeypot_Project_final' / 'var' / 'key_logger.log',
    'photo': BASE_DIR / 'honeypot' / 'Honeypot_Project_final' / 'var' / 'photo_metadata.log',
    'file': BASE_DIR / 'honeypot' / 'Honeypot_Project_final' / 'var' / 'file_analysis.log',
}

# Severity classification by port
PORT_SEVERITY = {
    22: 'critical',     # SSH
    23: 'critical',     # Telnet
    21: 'high',         # FTP
    80: 'medium',       # HTTP
    443: 'medium',      # HTTPS
    3306: 'critical',   # MySQL
    5432: 'critical',   # PostgreSQL
    8080: 'medium',     # HTTP Alt
    5000: 'medium',     # Flask honeypot
}

# Mock GeoIP database for coordinates (city → lat/lng)
GEOIP_MOCK = {
    '192.168.': {'city': 'Local Network', 'lat': 20.59, 'lng': 78.96},
    '10.':      {'city': 'Private Range', 'lat': 20.59, 'lng': 78.96},
    '172.':     {'city': 'Private Range', 'lat': 20.59, 'lng': 78.96},
    '127.':     {'city': 'Localhost', 'lat': 20.59, 'lng': 78.96},
}

# Fallback city coordinates for unknown IPs (rotated through)
WORLD_CITIES = [
    {'city': 'San Francisco', 'lat': 37.77, 'lng': -122.42},
    {'city': 'London', 'lat': 51.51, 'lng': -0.13},
    {'city': 'Moscow', 'lat': 55.76, 'lng': 37.62},
    {'city': 'Tokyo', 'lat': 35.68, 'lng': 139.65},
    {'city': 'Sydney', 'lat': -33.87, 'lng': 151.21},
    {'city': 'Beijing', 'lat': 39.90, 'lng': 116.41},
    {'city': 'São Paulo', 'lat': -23.55, 'lng': -46.63},
    {'city': 'Berlin', 'lat': 52.52, 'lng': 13.41},
    {'city': 'Dubai', 'lat': 25.20, 'lng': 55.27},
    {'city': 'Nairobi', 'lat': -1.29, 'lng': 36.82},
    {'city': 'Singapore', 'lat': 1.35, 'lng': 103.82},
    {'city': 'New York', 'lat': 40.71, 'lng': -74.01},
    {'city': 'Istanbul', 'lat': 41.01, 'lng': 28.98},
    {'city': 'Delhi', 'lat': 28.61, 'lng': 77.21},
    {'city': 'Los Angeles', 'lat': 34.05, 'lng': -118.24},
]

# ============================================================
# Logging Setup
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger('DefroxPot-RT')

# ============================================================
# Socket.IO Server
# ============================================================
sio = socketio.Server(
    cors_allowed_origins=CORS_ORIGINS,
    async_mode='eventlet',
    logger=False,
    engineio_logger=False,
)
app = socketio.WSGIApp(sio)

# Track connected clients
connected_clients = set()
# Attack frequency tracker (for severity escalation)
attack_timestamps = []
# City rotation index
city_index = 0


def get_geo_for_ip(ip_addr):
    """Resolve IP to mock GeoIP coordinates."""
    global city_index
    for prefix, geo in GEOIP_MOCK.items():
        if ip_addr.startswith(prefix):
            return geo

    # Rotate through world cities for unknown IPs
    geo = WORLD_CITIES[city_index % len(WORLD_CITIES)]
    city_index += 1
    return geo


def classify_severity(port=None, protocol='TCP'):
    """Classify attack severity based on port and frequency."""
    global attack_timestamps

    # Clean old timestamps (last 60 seconds)
    now = time.time()
    attack_timestamps = [t for t in attack_timestamps if now - t < 60]
    attack_timestamps.append(now)

    freq = len(attack_timestamps)

    # Frequency-based escalation
    if freq >= 15:
        return 'critical'
    elif freq >= 10:
        return 'high'

    # Port-based
    if port and port in PORT_SEVERITY:
        return PORT_SEVERITY[port]

    # Protocol-based defaults
    if protocol == 'ICMP':
        return 'medium'

    return 'low'


def build_packet(event_type, ip, protocol='TCP', port=None, ttl=None, extra=None):
    """Build the standardized JSON data packet."""
    geo = get_geo_for_ip(ip)
    severity = classify_severity(port, protocol)

    packet = {
        'type': event_type,           # "Attack" or "Ping"
        'ip': ip,
        'protocol': protocol,         # "TCP", "UDP", "ICMP"
        'port': port,
        'ttl': ttl,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'severity': severity,         # "low", "medium", "high", "critical"
        'coordinates': {
            'city': geo['city'],
            'lat': geo['lat'],
            'lng': geo['lng'],
        },
    }

    if extra:
        packet['details'] = extra

    return packet


# ============================================================
# Socket.IO Event Handlers
# ============================================================
@sio.event
def connect(sid, environ):
    connected_clients.add(sid)
    logger.info(f'Client connected: {sid} ({len(connected_clients)} total)')
    # Send initial status
    sio.emit('server_status', {
        'status': 'connected',
        'server_time': datetime.now(timezone.utc).isoformat(),
        'sniffing': SCAPY_AVAILABLE and args.sniff if 'args' in globals() else False,
        'log_watching': True,
        'connected_clients': len(connected_clients),
    }, to=sid)


@sio.event
def disconnect(sid):
    connected_clients.discard(sid)
    logger.info(f'Client disconnected: {sid} ({len(connected_clients)} remaining)')


@sio.event
def request_logs(sid, data):
    """Client requests current log snapshot."""
    log_type = data.get('type', 'web') if isinstance(data, dict) else 'web'
    log_path = LOG_PATHS.get(log_type)

    if log_path and log_path.exists():
        try:
            with open(log_path, 'r') as f:
                logs = [json.loads(line.strip()) for line in f if line.strip()]
            sio.emit('log_snapshot', {
                'type': log_type,
                'logs': logs[-50:],  # Last 50 entries
                'total': len(logs),
            }, to=sid)
        except Exception as e:
            sio.emit('error', {'message': f'Failed to read {log_type} logs: {str(e)}'}, to=sid)


# ============================================================
# Log File Watcher (Background Thread)
# ============================================================
class LogWatcher:
    """Watches honeypot log files for new entries and emits them via Socket.IO."""

    def __init__(self, sio_server):
        self.sio = sio_server
        self.file_positions = {}  # Track read position per file
        self.running = False

    def start(self):
        self.running = True
        # Initialize positions to end of file (only emit NEW entries)
        for name, path in LOG_PATHS.items():
            if path.exists():
                self.file_positions[name] = path.stat().st_size
            else:
                self.file_positions[name] = 0

        logger.info(f'Log watcher started — monitoring {len(LOG_PATHS)} log files')
        while self.running:
            self._check_logs()
            eventlet.sleep(1)  # Check every 1 second (non-blocking)

    def stop(self):
        self.running = False

    def _check_logs(self):
        for name, path in LOG_PATHS.items():
            if not path.exists():
                continue

            current_size = path.stat().st_size
            last_pos = self.file_positions.get(name, 0)

            if current_size > last_pos:
                # New data available
                try:
                    with open(path, 'r') as f:
                        f.seek(last_pos)
                        new_content = f.read()
                        self.file_positions[name] = f.tell()

                    for line in new_content.strip().split('\n'):
                        if not line.strip():
                            continue
                        try:
                            log_entry = json.loads(line.strip())
                            self._emit_log_entry(name, log_entry)
                        except json.JSONDecodeError:
                            continue

                except Exception as e:
                    logger.error(f'Error reading {name} log: {e}')

            elif current_size < last_pos:
                # File was truncated/rotated — reset position
                self.file_positions[name] = 0

    def _emit_log_entry(self, log_type, entry):
        """Convert a raw log entry to a standardized packet and emit it."""
        # Extract IP from different log formats
        ip = (entry.get('ip_addr') or
              entry.get('ip_address') or
              entry.get('source_ip') or
              entry.get('ip', '0.0.0.0'))

        # Extract port if available
        port = entry.get('port') or entry.get('dest_port')
        if port:
            try:
                port = int(port)
            except (ValueError, TypeError):
                port = None

        # Determine protocol
        protocol = entry.get('protocol', 'TCP').upper()

        # Build packet
        packet = build_packet(
            event_type='Ping' if protocol == 'ICMP' else 'Attack',
            ip=ip,
            protocol=protocol,
            port=port,
            extra={'log_type': log_type, 'raw': entry}
        )

        # Emit to all connected clients
        self.sio.emit('honeypot_activity', packet)

        # Also emit type-specific events
        if protocol == 'ICMP':
            self.sio.emit('network_ping', packet)
        else:
            self.sio.emit('network_attack', packet)

        logger.info(
            f'[{packet["severity"].upper():>8}] {packet["type"]:>6} | '
            f'{ip:>15} | {protocol}:{port or "-"} | '
            f'{packet["coordinates"]["city"]}'
        )


# ============================================================
# ICMP Packet Sniffer (Scapy — requires root/admin)
# ============================================================
class ICMPSniffer:
    """Raw packet sniffer using Scapy. Captures ICMP, TCP SYN, and UDP packets."""

    def __init__(self, sio_server):
        self.sio = sio_server
        self.running = False
        self.packet_count = 0

    def start(self):
        if not SCAPY_AVAILABLE:
            logger.error('Scapy not installed. Run: pip install scapy')
            return

        self.running = True
        logger.info('ICMP/Network sniffer started (requires root/admin privileges)')

        try:
            scapy_sniff(
                filter='icmp or (tcp[tcpflags] & tcp-syn != 0) or udp',
                prn=self._process_packet,
                stop_filter=lambda _: not self.running,
                store=False,
                timeout=None,
            )
        except PermissionError:
            logger.error(
                '\n[!] PERMISSION DENIED — Packet sniffing requires elevated privileges.\n'
                '    On Linux/macOS: sudo python realtime_server.py --sniff\n'
                '    On Windows: Run as Administrator\n'
            )
        except Exception as e:
            logger.error(f'Sniffer error: {e}')

    def stop(self):
        self.running = False

    def _process_packet(self, pkt):
        """Process a captured packet and emit via Socket.IO."""
        if not self.running or not connected_clients:
            return

        self.packet_count += 1

        try:
            if pkt.haslayer(ICMP) and pkt.haslayer(IP):
                icmp_layer = pkt[ICMP]
                ip_layer = pkt[IP]

                # Only process Echo Request (Type 8) — actual pings
                if icmp_layer.type == 8:
                    packet = build_packet(
                        event_type='Ping',
                        ip=ip_layer.src,
                        protocol='ICMP',
                        ttl=ip_layer.ttl,
                        extra={
                            'icmp_type': icmp_layer.type,
                            'icmp_code': icmp_layer.code,
                            'icmp_id': icmp_layer.id,
                            'icmp_seq': icmp_layer.seq,
                            'packet_size': len(pkt),
                        }
                    )
                    self.sio.emit('network_ping', packet)
                    self.sio.emit('honeypot_activity', packet)
                    logger.info(
                        f'[  PING  ] {ip_layer.src:>15} → ICMP Echo | '
                        f'TTL={ip_layer.ttl} SEQ={icmp_layer.seq}'
                    )

            elif pkt.haslayer(TCP) and pkt.haslayer(IP):
                ip_layer = pkt[IP]
                tcp_layer = pkt[TCP]

                # Only SYN packets (connection attempts)
                if tcp_layer.flags == 'S':
                    packet = build_packet(
                        event_type='Attack',
                        ip=ip_layer.src,
                        protocol='TCP',
                        port=tcp_layer.dport,
                        ttl=ip_layer.ttl,
                        extra={
                            'src_port': tcp_layer.sport,
                            'dst_port': tcp_layer.dport,
                            'flags': str(tcp_layer.flags),
                        }
                    )
                    self.sio.emit('network_attack', packet)
                    self.sio.emit('honeypot_activity', packet)

            elif pkt.haslayer(UDP) and pkt.haslayer(IP):
                ip_layer = pkt[IP]
                udp_layer = pkt[UDP]

                packet = build_packet(
                    event_type='Attack',
                    ip=ip_layer.src,
                    protocol='UDP',
                    port=udp_layer.dport,
                    ttl=ip_layer.ttl,
                    extra={
                        'src_port': udp_layer.sport,
                        'dst_port': udp_layer.dport,
                    }
                )
                self.sio.emit('network_attack', packet)
                self.sio.emit('honeypot_activity', packet)

        except Exception as e:
            logger.error(f'Packet processing error: {e}')


# ============================================================
# Main Entry Point
# ============================================================
def main():
    global args

    parser = argparse.ArgumentParser(
        description='DefroxPot Real-Time Streaming Server',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python realtime_server.py                 Start with log watching only
  python realtime_server.py --sniff         Enable ICMP/network packet sniffing
  python realtime_server.py --port 8888     Use custom port
  python realtime_server.py --sniff --port 9001
        """
    )
    parser.add_argument(
        '--sniff', action='store_true',
        help='Enable raw packet sniffing (requires root/admin)'
    )
    parser.add_argument(
        '--port', type=int, default=SOCKETIO_PORT,
        help=f'Port for Socket.IO server (default: {SOCKETIO_PORT})'
    )
    args = parser.parse_args()

    # Banner
    print(r"""
    ╔══════════════════════════════════════════════════╗
    ║     DefroxPot Real-Time Streaming Server         ║
    ║     ─────────────────────────────────────         ║
    ║     Socket.IO + Scapy ICMP Sniffer               ║
    ╚══════════════════════════════════════════════════╝
    """)
    logger.info(f'Starting on port {args.port}...')

    # --- Start Log Watcher (background thread, non-blocking) ---
    log_watcher = LogWatcher(sio)
    watcher_thread = threading.Thread(target=log_watcher.start, daemon=True)
    watcher_thread.start()
    logger.info('✓ Log watcher thread started')

    # --- Start ICMP Sniffer (background thread, non-blocking) ---
    sniffer = None
    if args.sniff:
        if not SCAPY_AVAILABLE:
            logger.warning('Scapy not installed — skipping packet sniffer')
            logger.warning('Install with: pip install scapy')
        else:
            sniffer = ICMPSniffer(sio)
            sniffer_thread = threading.Thread(target=sniffer.start, daemon=True)
            sniffer_thread.start()
            logger.info('✓ ICMP sniffer thread started')

    # --- Graceful shutdown ---
    def signal_handler(sig, frame):
        logger.info('\nShutting down...')
        log_watcher.stop()
        if sniffer:
            sniffer.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # --- Start Socket.IO Server ---
    logger.info(f'✓ Socket.IO server listening on http://0.0.0.0:{args.port}')
    logger.info(f'  Frontend connect URL: http://localhost:{args.port}')
    logger.info(f'  Sniffing: {"ENABLED" if args.sniff and SCAPY_AVAILABLE else "DISABLED"}')
    logger.info(f'  Log files: {len([p for p in LOG_PATHS.values() if p.exists()])} found\n')

    eventlet.wsgi.server(
        eventlet.listen(('0.0.0.0', args.port)),
        app,
        log_output=False,
    )


if __name__ == '__main__':
    main()
