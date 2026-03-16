import time
import random
from typing import List, Dict, Callable, Optional
import os
try:
    from scapy.all import sniff, wrpcap, get_if_list
except ImportError:
    sniff = None
    wrpcap = None
    get_if_list = None

def get_default_interface() -> str:
    # Try to auto-detect, fallback to eth0
    try:
        import netifaces
        gws = netifaces.gateways()
        return gws['default'][netifaces.AF_INET][1]
    except Exception:
        return 'eth0'

def capture_packets(interface: str, duration: Optional[int] = None, stop_flag: Optional[dict] = None, progress_callback: Optional[Callable[[int], None]] = None) -> List[dict]:
    """
    Capture packets using scapy if available and running as root, else simulate.
    """
    if sniff is not None and hasattr(os, 'geteuid') and os.geteuid() == 0:
        captured = []
        def _pkt_callback(pkt):
            captured.append(pkt)
            if progress_callback:
                progress_callback(len(captured))
            if stop_flag and stop_flag.get('stop'):
                return True  # Stop sniffing
        sniff(iface=interface, prn=_pkt_callback, timeout=duration, store=1, stop_filter=lambda x: stop_flag and stop_flag.get('stop'))
        # Convert scapy packets to summary dicts for dashboard
        packets = []
        for i, pkt in enumerate(captured, 1):
            packets.append({
                'id': i,
                'interface': interface,
                'size': len(pkt),
                'protocol': pkt.summary().split()[0] if hasattr(pkt, 'summary') else 'Unknown',
                'timestamp': time.time(),
                'original': pkt
            })
        return packets
    else:
        # Fallback to simulation
        packets = []
        protocols = ['TCP', 'UDP', 'ICMP', 'ARP']
        start_time = time.time()
        for i in range(1, 201):  # Simulate 200 packets
            if stop_flag and stop_flag.get('stop'):
                break
            pkt = {
                'id': i,
                'interface': interface,
                'size': random.randint(64, 1514),
                'protocol': random.choice(protocols),
                'timestamp': start_time + i * 0.03
            }
            packets.append(pkt)
            if progress_callback:
                progress_callback(i)
            time.sleep(0.03)  # Simulate time between packets
        return packets

def save_capture(packets: List[dict], filename: str):
    # Save as pcap if real packets, else as CSV
    if sniff is not None and packets and 'original' in packets[0]:
        wrpcap(filename, [pkt['original'] for pkt in packets])
    else:
        with open(filename, 'w') as f:
            f.write('id,interface,size,protocol,timestamp\n')
            for pkt in packets:
                f.write(f"{pkt['id']},{pkt['interface']},{pkt['size']},{pkt['protocol']},{pkt['timestamp']}\n")
