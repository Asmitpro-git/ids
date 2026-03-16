
"""
MITMProxy script for extracting HTTP features from network traffic.
"""
from mitmproxy import http
import pandas as pd
from mitmproxy import flow
from typing import List, Dict, Any

class PacketProcessor:
    """
    Processes HTTP requests using mitmproxy and extracts relevant features for analysis.
    """
    def __init__(self) -> None:
        self.data: List[Dict[str, Any]] = []

    def request(self, flow: http.HTTPFlow) -> None:
        """
        Process HTTP requests and extract features.
        Args:
            flow (http.HTTPFlow): The HTTP flow object from mitmproxy.
        """
        if flow.request:
            try:
                features = {
                    'src_ip': flow.client_conn.address[0],
                    'dst_ip': flow.request.host,
                    'protocol': 'TCP',
                    'packet_size': len(flow.request.content) if flow.request.content else 0,
                    'has_http': 1,
                    'url': flow.request.pretty_url,
                    'method': flow.request.method,
                    'headers': str(flow.request.headers),
                    'dst_port': flow.request.port,
                    'content': flow.request.content.decode('utf-8', errors='ignore') if flow.request.content else ''
                }
                self.data.append(features)
            except Exception as e:
                import logging
                logging.error(f"Error extracting features from HTTPFlow: {e}")

    def get_features(self) -> pd.DataFrame:
        """
        Return collected features as a pandas DataFrame.
        Returns:
            pd.DataFrame: DataFrame of extracted HTTP features.
        """
        return pd.DataFrame(self.data)

processor = PacketProcessor()

def get_processor() -> PacketProcessor:
    """
    Get the global PacketProcessor instance.
    Returns:
        PacketProcessor: The global packet processor.
    """
    return processor