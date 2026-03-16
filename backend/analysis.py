
"""
Module for rule-based scanning of network packet features for attacks.
"""
import re
import logging
from collections import Counter
from .packet_capture import extract_features
from .config import THRESHOLDS, SUSPICIOUS_DOMAINS
from typing import List
import pandas as pd

logging.basicConfig(level=logging.INFO)

def scan_for_attacks(features_df: pd.DataFrame) -> List[str]:
    """
    Rule-based scanning for multiple attacks.
    Args:
        features_df (pd.DataFrame): DataFrame containing extracted packet features.
    Returns:
        List[str]: List of alert messages for detected attacks or threats.
    """
    alerts: List[str] = []
    if features_df.empty:
        return alerts
    try:
        # Group by IP for IP-level attacks
        ip_packet_counts = Counter(features_df['src_ip'])
        ip_port_counts = features_df.groupby('src_ip')['dst_port'].nunique() if 'dst_port' in features_df.columns else Counter()
        ip_http_post_counts = features_df[features_df['method'] == 'POST'].groupby('src_ip').size() if 'method' in features_df.columns else Counter()

        for _, row in features_df.iterrows():
            # SQL Injection (keywords in payload or URL)
            if row.get('has_http', 0) == 1:
                payload = str(row.get('url', '')) + str(row.get('headers', '')) + str(row.get('content', ''))
                if re.search(r"(?i)(select|union|drop|insert|script|alert\()", payload):
                    alerts.append(f"Potential SQL Injection / XSS from {row['src_ip']} to {row['dst_ip']}")

            # Buffer Overflow (oversized packets)
            if row['packet_size'] > THRESHOLDS['buffer_overflow_packet_size']:
                alerts.append(f"Potential Buffer Overflow from {row['src_ip']} (packet size: {row['packet_size']})")

            # Ping of Death (oversized ICMP)
            if row['protocol'] == 'ICMP' and row['packet_size'] > THRESHOLDS['ping_of_death_packet_size']:
                alerts.append(f"Potential Ping of Death from {row['src_ip']} (packet size: {row['packet_size']})")

        # IP-level attacks
        for ip, count in ip_packet_counts.items():
            # DDoS (high packet rate from IP)
            if count > THRESHOLDS['ddos_packet_count']:
                alerts.append(f"Potential DDoS from {ip} (packet count: {count})")

            # Port Scanning (SYN to multiple ports from IP)
            if ip_port_counts.get(ip, 0) > THRESHOLDS['port_scan_ports']:
                alerts.append(f"Potential Port Scan from {ip} (ports scanned: {ip_port_counts[ip]})")

            # Brute Force (repeated HTTP POSTs from IP)
            if ip_http_post_counts.get(ip, 0) > THRESHOLDS['brute_force_post_count']:
                alerts.append(f"Potential Brute Force from {ip} (POST count: {ip_http_post_counts[ip]})")

            # Malware Indicators (suspicious URLs/headers)
            for _, r in features_df[features_df['src_ip'] == ip].iterrows():
                url = r.get('url', '')
                if any(domain in url for domain in SUSPICIOUS_DOMAINS):
                    alerts.append(f"Malware indicator: suspicious domain in URL from {ip}")
    except Exception as e:
        logging.error(f"Error in scan_for_attacks: {e}")
    return alerts if alerts else ["No threats detected"]