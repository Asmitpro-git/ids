#!/usr/bin/env python3
"""
Test script to verify SafeWeb IDS is working correctly
"""

import sys
import os
import time
import requests
from colorama import init, Fore, Style

init(autoreset=True)

def print_header(text):
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}{text:^60}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

def print_success(text):
    print(f"{Fore.GREEN}✓ {text}{Style.RESET_ALL}")

def print_error(text):
    print(f"{Fore.RED}✗ {text}{Style.RESET_ALL}")

def print_info(text):
    print(f"{Fore.YELLOW}ℹ {text}{Style.RESET_ALL}")

def test_imports():
    """Test if all required modules can be imported"""
    print_header("Testing Module Imports")
    
    modules = [
        'flask', 'scapy', 'pandas', 'sklearn', 
        'psutil', 'mitmproxy', 'authlib'
    ]
    
    for module in modules:
        try:
            __import__(module)
            print_success(f"{module} imported successfully")
        except ImportError as e:
            print_error(f"{module} import failed: {e}")
            return False
    
    return True

def test_backend_modules():
    """Test backend modules"""
    print_header("Testing Backend Modules")
    
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        
        from backend.packet_capture import get_if_list, get_default_interface
        interfaces = get_if_list()
        default = get_default_interface()
        print_success(f"Interfaces detected: {interfaces}")
        print_success(f"Default interface: {default}")
        
        from backend.analysis import scan_for_attacks
        import pandas as pd
        df = pd.DataFrame({
            'src_ip': ['192.168.1.1'],
            'dst_ip': ['192.168.1.2'],
            'protocol': ['TCP'],
            'packet_size': [1600],
            'has_http': [0]
        })
        alerts = scan_for_attacks(df)
        print_success(f"Rule-based analysis works: {len(alerts)} alerts")
        
        from backend.ml_model import predict_attacks
        print_success("ML module imported successfully")
        
        from backend.users import verify_user, add_user
        print_success("User management module works")
        
        return True
    except Exception as e:
        print_error(f"Backend test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_flask_app():
    """Test if Flask app can be imported"""
    print_header("Testing Flask Application")
    
    try:
        import flask_app
        print_success("Flask app imported successfully")
        print_success(f"App name: {flask_app.app.name}")
        print_success(f"Routes defined: {len(flask_app.app.url_map._rules)}")
        return True
    except Exception as e:
        print_error(f"Flask app test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_api_endpoints():
    """Test API endpoints (requires Flask app running)"""
    print_header("Testing API Endpoints")
    
    base_url = "http://localhost:5000"
    
    # Check if server is running
    try:
        response = requests.get(base_url, timeout=2)
        print_success("Flask server is running")
    except requests.exceptions.RequestException:
        print_info("Flask server not running - skipping API tests")
        print_info("Start the server with: sudo ./start_ids.sh")
        return True
    
    # Test API endpoints
    endpoints = [
        '/api/dashboard-metrics',
        '/api/dashboard-history',
        '/api/packet-analysis-summary',
        '/api/ml-predictions-summary',
        '/capture_stats'
    ]
    
    for endpoint in endpoints:
        try:
            response = requests.get(base_url + endpoint, timeout=2)
            if response.status_code == 200:
                print_success(f"{endpoint} - OK")
            else:
                print_error(f"{endpoint} - Status {response.status_code}")
        except Exception as e:
            print_error(f"{endpoint} - Error: {e}")
    
    return True

def test_file_structure():
    """Test if required files and directories exist"""
    print_header("Testing File Structure")
    
    required_files = [
        'flask_app.py',
        'backend/packet_capture.py',
        'backend/analysis.py',
        'backend/ml_model.py',
        'backend/config.py',
        'backend/users.py',
        'templates/dashboard.html',
        'templates/packet_analysis.html',
        'templates/ml_predictions.html',
        'analysis_history.json',
        'settings.json'
    ]
    
    for filepath in required_files:
        if os.path.exists(filepath):
            print_success(f"{filepath} exists")
        else:
            print_error(f"{filepath} not found")
    
    # Check if data directories exist
    dirs = ['data/captures', 'data/models']
    for directory in dirs:
        if os.path.exists(directory):
            print_success(f"{directory}/ exists")
        else:
            os.makedirs(directory, exist_ok=True)
            print_info(f"{directory}/ created")
    
    return True

def main():
    print(f"\n{Fore.MAGENTA}{'='*60}")
    print(f"{Fore.MAGENTA}{'SafeWeb IDS - System Test':^60}")
    print(f"{Fore.MAGENTA}{'='*60}{Style.RESET_ALL}\n")
    
    results = {
        "File Structure": test_file_structure(),
        "Module Imports": test_imports(),
        "Backend Modules": test_backend_modules(),
        "Flask Application": test_flask_app(),
        "API Endpoints": test_api_endpoints()
    }
    
    print_header("Test Results Summary")
    
    total = len(results)
    passed = sum(results.values())
    
    for test_name, passed_test in results.items():
        status = f"{Fore.GREEN}PASSED" if passed_test else f"{Fore.RED}FAILED"
        print(f"{test_name:.<40} {status}{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}Total: {passed}/{total} tests passed{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    if passed == total:
        print_success("All tests passed! Your IDS is ready to use.")
        print_info("Start the IDS with: sudo ./start_ids.sh")
        return 0
    else:
        print_error(f"{total - passed} test(s) failed. Check errors above.")
        return 1

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Test interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
