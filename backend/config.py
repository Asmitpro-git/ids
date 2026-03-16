
"""
Configuration for SafeWeb Packet Monitor IDS.
"""
# Configuration for SafeWeb Packet Monitor IDS

THRESHOLDS = {
    'ddos_packet_count': 50,           # Threshold for DDoS detection
    'port_scan_ports': 10,             # Threshold for port scan detection
    'brute_force_post_count': 5,       # Threshold for brute force POSTs
    'buffer_overflow_packet_size': 1500, # Threshold for buffer overflow
    'ping_of_death_packet_size': 65535   # Threshold for Ping of Death
}

SUSPICIOUS_DOMAINS = [
    'malicious.com',
    'phishing.net'
    # Add more known bad domains here
]
