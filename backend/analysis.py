
"""
Module for rule-based scanning of network packet features focused on DoS/DDoS.
"""
import logging
from collections import Counter
from .packet_capture import extract_features
from .config import THRESHOLDS
from typing import List
import pandas as pd

logging.basicConfig(level=logging.INFO)

def scan_for_attacks(features_df: pd.DataFrame) -> List[str]:
    """
    Rule-based scanning focused solely on DoS/DDoS-style volume anomalies.
    Args:
        features_df (pd.DataFrame): DataFrame containing extracted packet features.
    Returns:
        List[str]: List of alert messages for detected DoS/DDoS threats.
    """
    alerts: List[str] = []
    if features_df.empty:
        return alerts
    try:
        # Count packets per source IP to flag high-volume offenders
        ip_packet_counts = Counter(features_df['src_ip'])
        for ip, count in ip_packet_counts.items():
            if count > THRESHOLDS['ddos_packet_count']:
                alerts.append(f"Potential DoS/DDoS from {ip} (packet count: {count})")
    except Exception as e:
        logging.error(f"Error in scan_for_attacks: {e}")
    return alerts if alerts else ["No DoS/DDoS indicators detected"]