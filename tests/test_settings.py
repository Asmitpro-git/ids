import pytest
import os
import json
from flask_app import load_settings, save_settings, SETTINGS_FILE

def test_settings_persistence(tmp_path):
    test_file = tmp_path / 'settings.json'
    settings = {
        'thresholds': {'ddos_packet_count': 100},
        'notification_email': 'test@example.com',
        'ml_model': 'isolation_forest'
    }
    # Save settings
    save_settings(settings)
    # Load settings
    loaded = load_settings()
    assert loaded['thresholds'] == settings['thresholds']
    assert loaded['notification_email'] == settings['notification_email']
    assert loaded['ml_model'] == settings['ml_model']
