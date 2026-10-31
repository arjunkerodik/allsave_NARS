import threading
import time
from datetime import datetime
import logging
import random
import sys
import ctypes
import platform

# Prevent unprivileged Windows Npcap kernel driver hang
if sys.platform == 'win32':
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        is_admin = False
    if not is_admin:
        try:
            from scapy.libs import winpcapy
            winpcapy.pcap_findalldevs = lambda *args: -1
        except Exception:
            pass

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from scapy.layers.http import HTTPRequest
import os

from models import is_ip_blocked

class NetworkCollector:
    """Collects real network traffic logs using Scapy"""

    def __init__(self):
        self.logger = logging.getLogger('NetworkCollector')
        self.captured_packets = []
        self.max_packets = 100
        self.is_running = False
        self.capture_thread = None

        # --- NEW FLOW & METRIC TRACKING ---
        self.active_flows = {} # (tuple) -> {start_time, last_seen, bytes, packets}
        self.throughput = {'kbps': 0, 'pps': 0, 'total_bytes_window': 0, 'total_pkts_window': 0}
        self.last_stat_time = time.time()

        # Signatures for DPI-Lite
        self.signatures = {
            'SQL Injection': [b'UNION SELECT', b'OR 1=1', b'DROP TABLE', b'--'],
            'XSS Attack': [b'<script>', b'alert(', b'onerror='],
            'Path Traversal': [b'../../', b'/etc/passwd', b'C:\\Windows'],
            'Command Injection': [b'; cat ', b'; ls ', b'; dir', b'/bin/sh']
        }

        # The saved network model is not used on single packets. It needs 78 flow features, and
        # padding a packet's few values with zeros gave meaningless output. See utils/nids_engine.py.
        # 'unavailable' means no packets are being captured. Random packets are only produced
        # when explicitly enabled for a demo, and are labelled as simulated when stored.
        self.capture_status = 'starting'
        self.simulate_when_unavailable = os.environ.get('ALLSAFE_SIMULATED_TELEMETRY', '0') == '1'
        self.hostname = platform.node()

    def start_capture(self):
        """Start real-time packet capture"""
        if self.is_running:
            return

        self.is_running = True
        self.capture_thread = threading.Thread(target=self._capture_packets, daemon=True)
        self.capture_thread.start()
        self.logger.info("Network packet capture started")

    def stop_capture(self):
        """Stop packet capture"""
        self.is_running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        self.logger.info("Network packet capture stopped")

    def _capture_packets(self):
        """Capture packets in background thread"""
        sniff_failed = False
        while self.is_running:
            if not sniff_failed:
                try:
                    self.capture_status = 'live'
                    # Capture packets with a filter to reduce noise
                    sniff(
                        prn=self._process_packet,
                        filter="ip and (tcp or udp or icmp)",
                        store=0,
                        stop_filter=lambda x: not self.is_running,
                        timeout=1  # Check for stopping every second
                    )
                except Exception as e:
                    sniff_failed = True
                    if self.simulate_when_unavailable:
                        self.capture_status = 'simulated'
                        self.logger.warning(f"Live packet sniffing unavailable ({e}). Generating labelled simulated telemetry.")
                    else:
                        self.capture_status = 'unavailable'
                        self.logger.warning(f"Live packet sniffing unavailable ({e}). Network telemetry comes from uploads and simulations only.")

            if sniff_failed and self.is_running:
                if not self.simulate_when_unavailable:
                    time.sleep(5)
                    continue
                try:
                    self._generate_simulated_packet()
                    time.sleep(random.uniform(0.3, 1.2))
                except Exception:
                    time.sleep(1)

    def _generate_simulated_packet(self):
        """Generates realistic telemetry packets when raw socket sniffing is unavailable"""
        src_ip = random.choice(['192.168.1.100', '192.168.1.105', '192.168.1.120', '10.0.0.15'])
        dst_ip = random.choice(['8.8.8.8', '1.1.1.1', '142.250.190.46', '192.168.1.1', '104.24.11.89'])
        proto_choice = random.choices(['HTTP', 'HTTPS', 'DNS', 'OTHER'], weights=[35, 45, 15, 5])[0]

        if proto_choice == 'HTTP':
            sport = random.randint(49152, 65535)
            dport = 80
            pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags='PA')/Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
        elif proto_choice == 'HTTPS':
            sport = random.randint(49152, 65535)
            dport = 443
            pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags='PA')/Raw(load=b"\x16\x03\x01\x00\xa5\x01" + b"\x00"*random.randint(100, 1200))
        elif proto_choice == 'DNS':
            sport = random.randint(49152, 65535)
            dport = 53
            pkt = IP(src=src_ip, dst=dst_ip)/UDP(sport=sport, dport=dport)/Raw(load=b"\x12\x34\x01\x00\x00\x01\x00\x00")
        else:
            sport = random.randint(1024, 65535)
            dport = random.choice([22, 21, 3389, 8080])
            pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags='S')

        self._process_packet(pkt, origin='simulated_telemetry')

    def _process_packet(self, packet, origin='live'):
        """Process a captured packet and extract relevant information"""
        try:
            if IP in packet:
                ip_layer = packet[IP]

                # Check blocklist first
                if is_ip_blocked(ip_layer.src):
                    # We still log it but mark it as BLOCKED
                    pass

                # Basic packet information
                packet_info = {
                    'protocol': self._get_protocol(packet),
                    'origin': origin,
                    'hostname': self.hostname,
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': ip_layer.src,
                    'dst_ip': ip_layer.dst,
                    'src_port': None,
                    'dst_port': None,
                    'bytes': len(packet),
                    'flags': '',
                    'duration': 0.0, # Handled per-flow if needed, using 0.0 for now
                    'details': ''
                }

                # Extract port information and flags for TCP
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    packet_info['src_port'] = tcp_layer.sport
                    packet_info['dst_port'] = tcp_layer.dport
                    packet_info['flags'] = str(tcp_layer.flags)

                    # Protocol detection based on ports
                    ports = [tcp_layer.sport, tcp_layer.dport]
                    if any(p in [80, 8080] for p in ports): packet_info['protocol'] = 'HTTP'
                    elif any(p == 443 for p in ports): packet_info['protocol'] = 'HTTPS'
                    elif any(p == 22 for p in ports): packet_info['protocol'] = 'SSH'
                    elif any(p == 3389 for p in ports): packet_info['protocol'] = 'RDP'
                    elif any(p == 21 for p in ports): packet_info['protocol'] = 'FTP'

                # Extract port information for UDP
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    packet_info['src_port'] = udp_layer.sport
                    packet_info['dst_port'] = udp_layer.dport

                    # Protocol detection
                    ports = [udp_layer.sport, udp_layer.dport]
                    if any(p == 53 for p in ports): packet_info['protocol'] = 'DNS'
                    elif any(p in [67, 68] for p in ports): packet_info['protocol'] = 'DHCP'
                    elif any(p == 123 for p in ports): packet_info['protocol'] = 'NTP'

                # --- APPLY FLOW TRACKING ---
                flow_key = (packet_info['src_ip'], packet_info['dst_ip'], packet_info['src_port'], packet_info['dst_port'], packet_info['protocol'])
                now = time.time()

                if flow_key not in self.active_flows:
                    self.active_flows[flow_key] = {'start_time': now, 'last_seen': now, 'bytes': packet_info['bytes'], 'pkts': 1}
                else:
                    self.active_flows[flow_key]['last_seen'] = now
                    self.active_flows[flow_key]['bytes'] += packet_info['bytes']
                    self.active_flows[flow_key]['pkts'] += 1

                # Calculate Duration
                packet_info['duration'] = now - self.active_flows[flow_key]['start_time']
                packet_info['packet_count'] = self.active_flows[flow_key]['pkts']
                if TCP in packet:
                    tcp_flags = packet_info['flags']
                    packet_info['connection_status'] = (
                        'closed' if 'F' in tcp_flags or 'R' in tcp_flags
                        else 'attempted' if tcp_flags == 'S' else 'established')

                # Update metrics for throughput
                self.throughput['total_bytes_window'] += packet_info['bytes']
                self.throughput['total_pkts_window'] += 1

                # Build details string
                packet_info['details'] = f"{packet_info['protocol']} Traffic | Flags: {packet_info['flags']} | Size: {packet_info['bytes']} bytes"

                # --- SIGNATURE BASED DETECTION (DPI-Lite) ---
                if Raw in packet:
                    payload = packet[Raw].load
                    for sig_type, markers in self.signatures.items():
                        if any(m.lower() in payload.lower() for m in markers):
                            packet_info['is_malicious'] = True
                            packet_info['details'] += f" | !!! {sig_type.upper()} DETECTED IN PAYLOAD !!!"

                # Tag as blocked if relevant
                packet_info['is_blocked'] = is_ip_blocked(ip_layer.src)
                if packet_info['is_blocked']:
                    packet_info['details'] = "[ON-BLOCKLIST] " + packet_info['details']

                # Add to captured packets list
                self.captured_packets.append(packet_info)

                # Keep only recent packets
                if len(self.captured_packets) > self.max_packets:
                    self.captured_packets = self.captured_packets[-self.max_packets:]

        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")

    def _get_protocol(self, packet):
        """Determine the protocol of the packet"""
        if TCP in packet:
            return 'TCP'
        elif UDP in packet:
            return 'UDP'
        elif ICMP in packet:
            return 'ICMP'
        else:
            return 'OTHER'

    def collect_events(self):
        """Collect recent network events and update throughput metrics"""
        if not self.is_running:
            self.start_capture()

        # Update Throughput once per second (approx)
        now = time.time()
        time_diff = now - self.last_stat_time
        if time_diff >= 1.0:
            self.throughput['kbps'] = (self.throughput['total_bytes_window'] / 1024) / time_diff
            self.throughput['pps'] = self.throughput['total_pkts_window'] / time_diff
            # Reset window
            self.throughput['total_bytes_window'] = 0
            self.throughput['total_pkts_window'] = 0
            self.last_stat_time = now

        # Clean up stale flows (inactive > 60s)
        stale_keys = [k for k, v in self.active_flows.items() if now - v['last_seen'] > 60]
        for k in stale_keys: del self.active_flows[k]

        # Swap rather than copy-and-clear, so a packet arriving in between is not lost
        events, self.captured_packets = self.captured_packets, []

        return events

    def log_packet(self, src_ip, dst_ip, protocol, src_port, dst_port, length):
        """Log a specific packet (for manual logging)"""
        event = {
            'protocol': protocol,
            'timestamp': datetime.now().isoformat(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'length': length
        }
        return event

    def log_dns_query(self, src_ip, domain):
        """Log a DNS query (for manual logging)"""
        event = {
            'protocol': 'DNS',
            'timestamp': datetime.now().isoformat(),
            'src_ip': src_ip,
            'dst_ip': '8.8.8.8',  # Google DNS
            'src_port': 54321,  # Random high port
            'dst_port': 53,
            'length': 64
        }
        return event

    def log_http_request(self, src_ip, dst_ip, method, path):
        """Log an HTTP request (for manual logging)"""
        event = {
            'protocol': 'HTTP',
            'timestamp': datetime.now().isoformat(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': random.randint(1024, 65535),
            'dst_port': 80,
            'length': random.randint(512, 4096)
        }
        return event
