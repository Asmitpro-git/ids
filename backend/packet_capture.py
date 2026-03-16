
"""
Packet capture and feature extraction utilities for SafeWeb IDS.
"""
import os
import logging
from scapy.all import sniff, wrpcap, IP, TCP, UDP
from scapy.layers.http import HTTPRequest
import pandas as pd
from datetime import datetime
from subprocess import Popen, DEVNULL
from mitmproxy.tools.main import mitmdump
from backend.mitm_script import get_processor

logging.basicConfig(level=logging.INFO)

def get_if_list():
    """Get list of available network interfaces."""
    try:
        interfaces = os.listdir('/sys/class/net/')
        return [iface for iface in interfaces if iface != 'lo']
    except Exception:
        # Fallback if /sys/class/net/ is not available
        try:
            import psutil
            return [iface for iface in psutil.net_if_addrs().keys() if iface != 'lo']
        except Exception:
            return ['eth0', 'wlan0', 'enp0s3']

def get_default_interface():
    """Get default network interface."""
    try:
        interfaces = get_if_list()
        logging.info(f"Available interfaces: {interfaces}")
        if interfaces:
            logging.info(f"Defaulting to interface: {interfaces[0]}")
            return interfaces[0]
        return 'eth0'
    except Exception as e:
        logging.error(f"Error getting default interface: {e}")
        return 'eth0'

def capture_packets(interface=None, count=100, filter_str='ip'):
    """Capture packets using Scapy and mitmproxy for HTTPS. Default filter is 'ip' for all IP traffic."""
    if os.geteuid() != 0:
        logging.error("Packet capture requires root privileges. Run with sudo.")
        raise PermissionError("Packet capture requires root privileges. Run with sudo.")
    if not interface:
        interface = get_default_interface()
    # Log available interfaces and their status
    try:
        import psutil
        net_if_stats = psutil.net_if_stats()
        for iface, stats in net_if_stats.items():
            logging.info(f"Interface {iface}: isup={stats.isup}, duplex={stats.duplex}, speed={stats.speed}, mtu={stats.mtu}")
    except Exception as e:
        logging.warning(f"Could not get interface stats: {e}")
    logging.info(f"Starting packet capture on interface: {interface}")
    try:
        # Start mitmproxy in transparent mode with custom script
        mitmproxy_installed = True
        try:
            mitm_proc = Popen(
                ['mitmdump', '-s', 'backend/mitm_script.py', '--mode', 'transparent'],
                stdout=DEVNULL, stderr=DEVNULL
            )
        except Exception as mitm_err:
            logging.error(f"mitmproxy failed to start: {mitm_err}")
            mitmproxy_installed = False
            mitm_proc = None
        # Capture with Scapy (simultaneously)
        try:
            packets = sniff(iface=interface, count=count, filter=filter_str, timeout=60)
        except Exception as scapy_err:
            logging.error(f"Scapy sniff failed: {scapy_err}")
            packets = []
        # Get mitmproxy features
        processor = get_processor()
        mitm_features = processor.get_features() if mitmproxy_installed else pd.DataFrame()
        # Stop mitmproxy
        if mitm_proc:
            mitm_proc.terminate()
            mitm_proc.wait()
        # Combine Scapy and mitmproxy features
        scapy_features = extract_features_scapy(packets)
        logging.info(f"Scapy captured {len(packets)} packets. Mitmproxy features: {len(mitm_features)} rows.")
        return packets, pd.concat([scapy_features, mitm_features], ignore_index=True)
    except Exception as e:
        logging.error(f"Error capturing packets: {e}")
        return [], pd.DataFrame()

def save_capture(packets, filename=None):
    """Save packets to .pcap file."""
    if not packets:
        return None
    if not filename:
        filename = f"data/captures/capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    os.makedirs('data/captures', exist_ok=True)
    wrpcap(filename, packets)
    return filename

def extract_features_scapy(packets):
    """Extract features from Scapy packets (for non-HTTP/HTTPS fallback)."""
    data = []
    for pkt in packets:
        if IP in pkt:
            features = {
                'src_ip': pkt[IP].src,
                'dst_ip': pkt[IP].dst,
                'protocol': 'TCP' if TCP in pkt else 'UDP' if UDP in pkt else 'Other',
                'packet_size': len(pkt),
                'has_http': 1 if HTTPRequest in pkt else 0,
                'url': '',
                'method': '',
                'headers': ''
            }
            data.append(features)
    return pd.DataFrame(data)

def extract_features(packets):
    """Extract features using Scapy and mitmproxy."""
    packets, features_df = capture_packets()
    return features_df

# ... (existing imports and functions) ...

def extract_features_scapy(packets):
    """Extract features from Scapy packets."""
    data = []
    for pkt in packets:
        if IP in pkt:
            features = {
                'src_ip': pkt[IP].src,
                'dst_ip': pkt[IP].dst,
                'protocol': 'TCP' if TCP in pkt else 'UDP' if UDP in pkt else 'Other',
                'packet_size': len(pkt),
                'has_http': 1 if HTTPRequest in pkt else 0,
                'url': '',
                'method': '',
                'headers': '',
                'dst_port': pkt[TCP].dport if TCP in pkt else pkt[UDP].dport if UDP in pkt else 0,
                'content': str(pkt.payload) if pkt.payload else ''
            }
            data.append(features)
    return pd.DataFrame(data)