# ...existing code...

# Place this route after app is defined and with other routes





import sys
import os
import threading
import time
import logging
from flask import Flask, render_template, redirect, url_for, request, send_from_directory, jsonify, flash, session
from werkzeug.utils import secure_filename

import pandas as pd
from flask_wtf import CSRFProtect
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

# Setup logging
logging.basicConfig(level=logging.INFO)

# Ensure backend is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from backend.packet_capture import capture_packets, save_capture, get_default_interface, get_if_list
import json
















app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.abspath(os.path.join(os.path.dirname(__file__), '../data/captures'))
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB limit
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev_secret_key')

# AI Assistant backend endpoint (moved after app definition)
from flask import request
@app.route('/api/ai-assistant', methods=['POST'])
@login_required
def ai_assistant_api():
    data = request.get_json()
    query = (data.get('query') or '').strip().lower()
    # Simple command recognition (expand as needed)
    page_map = {
        'dashboard': '/dashboard',
        'packet analysis': '/packet-analysis',
        'ml predictions': '/ml-predictions',
        'visualizations': '/visualizations',
        'saved captures': '/saved-captures',
        'settings': '/settings',
        'ai assistant': '/ai-assistant'
    }
    for key in page_map:
        if f'open {key}' in query or query == key:
            return {'type': 'redirect', 'url': page_map[key], 'message': f'Opening {key} page...'}
    if 'what is this project' in query or 'about this project' in query:
        return {'type': 'answer', 'message': 'This is SafeWeb IDS, a Flask-based intrusion detection system with ML and rule-based analysis, visualizations, and user authentication.'}
    if 'who made you' in query or 'author' in query:
        return {'type': 'answer', 'message': 'This project was created by Asmit Kumar and contributors.'}
    if 'how to use' in query:
        return {'type': 'answer', 'message': 'Navigate using the sidebar or ask me to open any page. You can upload packet captures, view analysis, and manage settings.'}
    # Fallback: echo
    return {'type': 'answer', 'message': f'Sorry, I can only open project pages or answer basic questions for now. You asked: {query}'}

from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

# Export analysis history as CSV (moved after app definition)
@app.route('/api/export-analysis-history')
@login_required
def export_analysis_history():
    import csv
    import io
    import json
    history_path = os.path.join(os.path.dirname(__file__), 'analysis_history.json')
    if os.path.exists(history_path):
        with open(history_path, 'r') as f:
            history = json.load(f)
    else:
        history = []
    # Prepare CSV
    output = io.StringIO()
    writer = csv.writer(output)
    # Write header
    writer.writerow(['timestamp', 'filename', 'alerts', 'ml_predictions'])
    for entry in history:
        writer.writerow([
            entry.get('timestamp', ''),
            entry.get('filename', ''),
            '; '.join(entry.get('alerts', [])),
            '; '.join(entry.get('ml_predictions', []))
        ])
    output.seek(0)
    from flask import Response
    return Response(output.getvalue(), mimetype='text/csv', headers={"Content-Disposition": "attachment;filename=analysis_history.csv"})

# Flask-Limiter setup (after app is defined)
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    limiter = Limiter(get_remote_address, app=app, default_limits=["100 per minute"])
except ImportError:
    limiter = None

# Flask-Login setup

from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from backend.users import verify_user

from authlib.integrations.flask_client import OAuth
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Simple user class
class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(user_id):
    from backend.users import USERS
    return User(user_id) if user_id in USERS else None



# Google OAuth setup with Authlib
oauth = OAuth(app)
oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID', 'your-client-id'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET', 'your-client-secret'),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'}
)
# GitHub OAuth setup with Authlib
oauth.register(
    name='github',
    client_id=os.environ.get('GITHUB_CLIENT_ID', 'your-github-client-id'),
    client_secret=os.environ.get('GITHUB_CLIENT_SECRET', 'your-github-client-secret'),
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'}
)

# Login route
@app.route('/login', methods=['GET', 'POST'])

def login():
    error = None
    if request.method == 'POST':
        # Input sanitization for registration/login
        import re
        def sanitize(text):
            return re.sub(r'[^\w.@+-]', '', text)
        # Registration logic
        if request.form.get('register') == '1':
            new_username = sanitize(request.form.get('new_username', ''))
            new_password = sanitize(request.form.get('new_password', ''))
            if not new_username or not new_password:
                error = 'Username and password required for registration.'
            elif verify_user(new_username, new_password):
                error = 'User already exists.'
            else:
                from backend.users import add_user
                add_user(new_username, new_password)
                flash('Account created successfully! You can now log in.', 'success')
                return redirect(url_for('login'))
        else:
            # Login logic
            username = sanitize(request.form.get('username', ''))
            password = sanitize(request.form.get('password', ''))
            if verify_user(username, password):
                login_user(User(username))
                flash('Logged in successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid username or password.'
    return render_template('login.html', error=error)



# Google OAuth login with Authlib
@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_authorized', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/login/google/authorized')
def google_authorized():
    token = oauth.google.authorize_access_token()
    userinfo = oauth.google.get('userinfo').json()
    username = userinfo.get('email')
    login_user(User('admin'))  # For demo, treat Google login as admin
    flash('Logged in with Google!', 'success')
    return redirect(url_for('dashboard'))

# GitHub OAuth login with Authlib
@app.route('/login/github')
def github_login():
    redirect_uri = url_for('github_authorized', _external=True)
    return oauth.github.authorize_redirect(redirect_uri)

@app.route('/login/github/authorized')
def github_authorized():
    token = oauth.github.authorize_access_token()
    userinfo = oauth.github.get('user').json()
    username = userinfo.get('login')
    login_user(User('admin'))  # For demo, treat GitHub login as admin
    flash('Logged in with GitHub!', 'success')
    return redirect(url_for('dashboard'))

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))



# Persistent analysis history
ANALYSIS_HISTORY_FILE = os.path.join(os.path.dirname(__file__), 'analysis_history.json')

def load_analysis_history():
    if os.path.exists(ANALYSIS_HISTORY_FILE):
        with open(ANALYSIS_HISTORY_FILE, 'r') as f:
            try:
                data = json.load(f)
                if isinstance(data, list):
                    return data
                else:
                    # If file contains a dict, convert to list of its values
                    return list(data.values())
            except Exception:
                return []
    return []

def save_analysis_history(history):
    with open(ANALYSIS_HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2)

# Enable CSRF protection
csrf = CSRFProtect(app)

# Thread safety for IDS status
ids_status = {'online': False, 'thread': None, 'stop': False, 'protocol_counts': {}, 'total_bytes': 0, 'lock': threading.Lock()}

def start_packet_capture_thread():
    with ids_status['lock']:
        ids_status['online'] = True
        ids_status['stop'] = False
        ids_status['protocol_counts'] = {}
        ids_status['total_bytes'] = 0
    try:
        interface = ids_status.get('selected_interface', get_default_interface())
        save_dir = app.config['UPLOAD_FOLDER']
        os.makedirs(save_dir, exist_ok=True)
        filename = f"capture_{time.strftime('%Y%m%d_%H%M%S')}.pcap"
        save_path = os.path.join(save_dir, filename)
        logging.info(f"Starting packet capture thread on interface: {interface}")
        packets, features_df = capture_packets(interface)
        logging.info(f"Captured {len(packets)} packets on interface {interface}")
        if not packets:
            logging.error(f"No packets captured on interface {interface}. Check interface and permissions.")
            with ids_status['lock']:
                ids_status['last_error'] = f"No packets captured on interface {interface}. Check interface and permissions."
        for pkt in packets:
            proto = 'TCP' if pkt.haslayer('TCP') else 'UDP' if pkt.haslayer('UDP') else 'Other'
            pkt_size = len(pkt)
            with ids_status['lock']:
                ids_status['protocol_counts'][proto] = ids_status['protocol_counts'].get(proto, 0) + 1
                ids_status['total_bytes'] += pkt_size
        logging.info(f"Protocol counts: {ids_status['protocol_counts']}, Total bytes: {ids_status['total_bytes']}")
        save_capture(packets, save_path)

        # Prepare analysis summary for dashboard/history (live capture)
        from backend.packet_capture import extract_features_scapy
        from backend.analysis import scan_for_attacks
        from backend.ml_model import predict_attacks
        
        features = extract_features_scapy(packets)
        
        # Rule-based analysis
        rule_alerts = scan_for_attacks(features) if not features.empty else []
        
        # ML-based analysis
        try:
            ml_predictions = predict_attacks(features)
        except Exception as ml_err:
            logging.error(f"ML prediction error: {ml_err}")
            ml_predictions = ["ML model not available"]
        
        summary = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'filename': filename,
            'total_packets': len(packets),
            'alerts': rule_alerts,
            'ml_predictions': ml_predictions,
            'protocol_counts': {k: int(v) for k, v in dict(features['protocol'].value_counts()).items()} if not features.empty else {}
        }
        history = load_analysis_history()
        history.append(summary)
        save_analysis_history(history)
    except Exception as e:
        logging.error(f"Error during packet capture thread: {e}")
        import traceback
        traceback.print_exc()
        with ids_status['lock']:
            ids_status['last_error'] = str(e)
    with ids_status['lock']:
        ids_status['online'] = False
        ids_status['thread'] = None

def stop_packet_capture():
    with ids_status['lock']:
        ids_status['stop'] = True

@app.route('/capture_stats')
def capture_stats():
    with ids_status['lock']:
        return jsonify({
            'online': ids_status['online'],
            'packets_captured': sum(ids_status['protocol_counts'].values()),
            'protocol_counts': ids_status['protocol_counts'],
            'total_bytes': ids_status['total_bytes']
        })

def is_valid_pcap(file_storage):
    """Check extension and magic number for .pcap files."""
    if not hasattr(file_storage, 'filename') or not file_storage.filename.lower().endswith('.pcap'):
        return False
    try:
        pos = file_storage.stream.tell()
        file_storage.stream.seek(0)
        magic = file_storage.stream.read(4)
        file_storage.stream.seek(pos)
        # Standard pcap magic numbers: d4 c3 b2 a1 or a1 b2 c3 d4
        return magic in [b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4']
    except Exception:
        return False
def is_valid_pcap(file_storage):
    """Check extension and magic number for .pcap files."""
    if not hasattr(file_storage, 'filename') or not file_storage.filename.lower().endswith('.pcap'):
        return False
    try:
        pos = file_storage.stream.tell()
        file_storage.stream.seek(0)
        magic = file_storage.stream.read(4)
        file_storage.stream.seek(pos)
        # Standard pcap magic numbers: d4 c3 b2 a1 or a1 b2 c3 d4
        return magic in [b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4']
    except Exception:
        return False

@app.route('/', methods=['GET', 'POST'])
def home():
    packets, features = [], pd.DataFrame()
    rule_alerts, ml_predictions = [], []
    selected_file = None
    captures_dir = app.config['UPLOAD_FOLDER']
    files = [f for f in os.listdir(captures_dir) if f.endswith('.pcap')] if os.path.exists(captures_dir) else []
    upload_error = None
    with ids_status['lock']:
        status = 'Online' if ids_status['online'] else 'Offline'
        last_error = ids_status.get('last_error')

    # Interface selection
    interfaces = get_if_list()
    selected_interface = request.form.get('interface') if request.method == 'POST' else (ids_status.get('selected_interface') or interfaces[0])
    ids_status['selected_interface'] = selected_interface

    # Handle start/stop capture buttons
    if request.method == 'POST':
        if 'start_capture' in request.form:
            if not ids_status['online'] or not ids_status['thread'] or not ids_status['thread'].is_alive():
                ids_status['selected_interface'] = request.form.get('interface', interfaces[0])
                t = threading.Thread(target=start_packet_capture_thread, daemon=True)
                ids_status['thread'] = t
                t.start()
                status = 'Online'
        elif 'stop_capture' in request.form:
            stop_packet_capture()
            status = 'Offline'

    # Handle file upload
    if 'file' in (getattr(request, 'files', {}) or {}):
        file = request.files['file']
        filename = secure_filename(file.filename)
        # Prevent directory traversal and only allow .pcap
        if '/' in filename or '\\' in filename or not filename.endswith('.pcap'):
            upload_error = 'Invalid file name or extension.'
            logging.warning(f"Rejected upload: suspicious filename {file.filename}")
        elif not is_valid_pcap(file):
            upload_error = 'Uploaded file is not a valid .pcap file.'
            logging.warning(f"Rejected upload: invalid pcap content for {file.filename}")
        else:
            save_path = os.path.join(captures_dir, filename)
            if os.path.exists(save_path):
                upload_error = f'File {filename} already exists.'
                logging.info(f"Rejected upload: duplicate file {filename}")
            else:
                try:
                    file.save(save_path)
                    files.append(filename)
                    selected_file = filename
                except Exception as e:
                    upload_error = f'Error saving file: {e}'
                    logging.error(f"Error saving uploaded file {filename}: {e}")

    # Handle file selection
    if request.method == 'POST' and 'selected_file' in request.form:
        selected_file = request.form.get('selected_file') or selected_file


    # If a file is selected, process it and persist results
    if selected_file:
        try:
            file_path = os.path.join(captures_dir, selected_file)
            from scapy.all import rdpcap
            packets = rdpcap(file_path)
            from backend.packet_capture import extract_features_scapy
            from backend.analysis import scan_for_attacks
            from backend.ml_model import predict_attacks
            
            features = extract_features_scapy(packets)
            
            # Rule-based analysis
            rule_alerts = scan_for_attacks(features) if not features.empty else []
            
            # ML-based analysis
            try:
                ml_predictions = predict_attacks(features)
            except Exception as ml_err:
                logging.error(f"ML prediction error: {ml_err}")
                ml_predictions = ["ML model not available"]
            
            # Save analysis result to history
            history = load_analysis_history()
            history.append({
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'filename': selected_file,
                'total_packets': len(packets),
                'alerts': rule_alerts,
                'ml_predictions': ml_predictions,
                'protocol_counts': dict(features['protocol'].value_counts()) if not features.empty else {}
            })
            save_analysis_history(history)
        except Exception as e:
            upload_error = f"Error processing file: {e}"
            logging.error(f"Error processing file {selected_file}: {e}")

    metrics = {
        'packets_captured': len(packets),
        'threats_detected': len([a for a in rule_alerts if "Potential" in a or "DDoS" in a]),
        'ml_anomalies': sum(1 for pred in ml_predictions if "Attack" in pred),
        'security_status': "High Threat" if ml_predictions and any("Attack" in p for p in ml_predictions) else "Normal"
    }
    return render_template('dashboard.html', metrics=metrics, rule_alerts=rule_alerts, ml_predictions=ml_predictions, files=files, selected_file=selected_file, upload_error=upload_error, ids_status=status, interfaces=interfaces, selected_interface=selected_interface, last_error=last_error)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    # Show recent analysis history on dashboard
    history = load_analysis_history()
    recent_history = history[-10:] if history else []
    # Provide same context as home route
    packets, features = [], pd.DataFrame()
    rule_alerts, ml_predictions = [], []
    selected_file = None
    captures_dir = app.config['UPLOAD_FOLDER']
    files = [f for f in os.listdir(captures_dir) if f.endswith('.pcap')] if os.path.exists(captures_dir) else []
    upload_error = None
    with ids_status['lock']:
        status = 'Online' if ids_status['online'] else 'Offline'
        last_error = ids_status.get('last_error')
    interfaces = get_if_list()
    selected_interface = request.form.get('interface') if request.method == 'POST' else (ids_status.get('selected_interface') or interfaces[0])
    ids_status['selected_interface'] = selected_interface

    # Handle start/stop capture buttons
    if request.method == 'POST':
        if 'start_capture' in request.form:
            if not ids_status['online'] or not ids_status['thread'] or not ids_status['thread'].is_alive():
                ids_status['selected_interface'] = request.form.get('interface', interfaces[0])
                t = threading.Thread(target=start_packet_capture_thread, daemon=True)
                ids_status['thread'] = t
                t.start()
                status = 'Online'
        elif 'stop_capture' in request.form:
            stop_packet_capture()
            status = 'Offline'
    metrics = {
        'packets_captured': len(packets),
        'threats_detected': len([a for a in rule_alerts if "Potential" in a or "DDoS" in a]),
        'ml_anomalies': sum(1 for pred in ml_predictions if "Attack" in pred),
        'security_status': "High Threat" if ml_predictions and any("Attack" in p for p in ml_predictions) else "Normal"
    }
    return render_template(
        'dashboard.html',
        metrics=metrics,
        rule_alerts=rule_alerts,
        ml_predictions=ml_predictions,
        files=files,
        selected_file=selected_file,
        upload_error=upload_error,
        ids_status=status,
        interfaces=interfaces,
        selected_interface=selected_interface,
        recent_history=recent_history,
        last_error=last_error
    )

@app.route('/packet-analysis', methods=['GET', 'POST'])
def packet_analysis():
    history = load_analysis_history()
    from collections import Counter

    protocol_counts = Counter()
    total_packets = 0
    threats_detected = 0
    ml_anomalies = 0
    for entry in history:
        total_packets += entry.get('total_packets', 0)
        threats_detected += len(entry.get('alerts', []))
        ml_anomalies += sum(1 for p in entry.get('ml_predictions', []) if 'Anomaly' in p or 'Attack' in p)
        for proto, count in entry.get('protocol_counts', {}).items():
            protocol_counts[proto] += count

    summary = {
        'total_packets': total_packets,
        'threats_detected': threats_detected,
        'ml_anomalies': ml_anomalies,
        'protocols': ', '.join(protocol_counts.keys()) if protocol_counts else 'N/A',
        'protocol_counts': dict(protocol_counts)
    }

    # Build table rows derived from alerts/history (best-effort since per-packet data isn't stored)
    packets = []
    for entry in history:
        ts = entry.get('timestamp', '')
        proto_hint = next(iter(entry.get('protocol_counts', {}).keys()), 'N/A')
        alerts = entry.get('alerts', [])
        if alerts:
            for alert in alerts:
                m = re.search(r'from ([\d\.]+)', alert)
                src_ip = m.group(1) if m else 'Unknown'
                packets.append({
                    'timestamp': ts,
                    'src_ip': src_ip,
                    'dst_ip': 'N/A',
                    'protocol': proto_hint,
                    'packet_size': entry.get('total_packets', 0),
                    'threat': True
                })
        else:
            packets.append({
                'timestamp': ts,
                'src_ip': 'N/A',
                'dst_ip': 'N/A',
                'protocol': proto_hint,
                'packet_size': entry.get('total_packets', 0),
                'threat': False
            })

    return render_template('packet_analysis.html', summary=summary, packets=packets)

@app.route('/ml-predictions')
def ml_predictions():
    history = load_analysis_history()
    anomaly_counts = {'Anomaly': 0, 'Normal': 0}
    predictions = []
    last_scan_time = 'N/A'

    for entry in history:
        last_scan_time = entry.get('timestamp', last_scan_time)
        for p in entry.get('ml_predictions', []):
            label = 'Anomaly' if ('Anomaly' in p or 'Attack' in p) else 'Normal'
            anomaly_counts[label] += 1
            m = re.search(r'from ([\d\.]+)', p)
            src_ip = m.group(1) if m else 'Unknown'
            predictions.append({
                'timestamp': entry.get('timestamp', ''),
                'src_ip': src_ip,
                'dst_ip': 'N/A',
                'protocol': 'N/A',
                'label': label,
                'confidence': 1.0 if label == 'Anomaly' else 0.5
            })

    summary = {
        'total_predictions': sum(anomaly_counts.values()),
        'anomalies_detected': anomaly_counts['Anomaly'],
        'last_scan_time': last_scan_time,
        'anomaly_counts': anomaly_counts
    }

    return render_template('ml_predictions.html', summary=summary, predictions=predictions)

def _build_visualization_data(date_start=None, date_end=None, protocol_filter=None):
    """Aggregate analysis history into visualization-friendly structures."""
    history = load_analysis_history()

    def within_range(ts):
        if not ts:
            return False
        try:
            date_part = ts.split(' ')[0]
            if date_start and date_part < date_start:
                return False
            if date_end and date_part > date_end:
                return False
            return True
        except Exception:
            return True

    filtered = []
    for entry in history:
        if within_range(entry.get('timestamp', '')):
            if protocol_filter:
                if protocol_filter not in entry.get('protocol_counts', {}):
                    continue
            filtered.append(entry)

    from collections import Counter, defaultdict
    protocol_counts = Counter()
    traffic_trend = []
    threat_timeline = defaultdict(int)
    ml_anomaly_trend = defaultdict(int)
    total_packets = 0
    threats_detected = 0
    ml_anomalies = 0

    for entry in filtered:
        ts = entry.get('timestamp', '')
        date = ts.split(' ')[0] if ts else ''
        pkt_count = entry.get('total_packets', 0)
        total_packets += pkt_count
        alerts = entry.get('alerts', [])
        threats_detected += len(alerts)
        traffic_trend.append((ts, pkt_count))
        threat_timeline[date] += len(alerts)
        for proto, count in entry.get('protocol_counts', {}).items():
            protocol_counts[proto] += count
        preds = entry.get('ml_predictions', [])
        anomaly_count = sum(1 for p in preds if 'Anomaly' in p or 'Attack' in p)
        ml_anomaly_trend[date] += anomaly_count
        ml_anomalies += anomaly_count

    traffic_trend = sorted(traffic_trend, key=lambda x: x[0])

    summary = {
        'total_packets': total_packets,
        'threats_detected': threats_detected,
        'ml_anomalies': ml_anomalies
    }

    traffic_data = {
        'labels': [ts for ts, _ in traffic_trend],
        'data': [count for _, count in traffic_trend]
    }
    protocol_data = {
        'labels': list(protocol_counts.keys()),
        'data': list(protocol_counts.values())
    }
    threat_data = {
        'labels': list(threat_timeline.keys()),
        'data': list(threat_timeline.values())
    }
    ml_anomaly_data = {
        'labels': list(ml_anomaly_trend.keys()),
        'data': list(ml_anomaly_trend.values())
    }

    return summary, traffic_data, protocol_data, threat_data, ml_anomaly_data


@app.route('/visualizations')
def visualizationvisualizations():
    date_start = request.args.get('date_start') or None
    date_end = request.args.get('date_end') or None
    protocol_filter = request.args.get('protocol') or None
    summary, traffic_data, protocol_data, threat_data, ml_anomaly_data = _build_visualization_data(
        date_start=date_start, date_end=date_end, protocol_filter=protocol_filter
    )
    return render_template(
        'visualizations.html',
        summary=summary,
        traffic_data=traffic_data,
        protocol_data=protocol_data,
        threat_data=threat_data,
        ml_anomaly_data=ml_anomaly_data
    )

# API endpoint for visualization data
@app.route('/api/visualization-data')
def api_visualization_data():
    date_start = request.args.get('date_start') or None
    date_end = request.args.get('date_end') or None
    protocol_filter = request.args.get('protocol') or None
    summary, traffic_data, protocol_data, threat_data, ml_anomaly_data = _build_visualization_data(
        date_start=date_start, date_end=date_end, protocol_filter=protocol_filter
    )
    return jsonify({
        'summary': summary,
        'traffic': traffic_data,
        'protocol': protocol_data,
        'threat': threat_data,
        'ml_anomaly': ml_anomaly_data,
        'settings': load_settings()
    })

@app.route('/saved-captures')
def saved_captures():
    captures_dir = app.config['UPLOAD_FOLDER']
    files = [f for f in os.listdir(captures_dir) if f.endswith('.pcap')] if os.path.exists(captures_dir) else []
    captures = []
    for f in files:
        path = os.path.join(captures_dir, f)
        size = f"{os.path.getsize(path) // 1024} KB"
        date = time.strftime('%Y-%m-%d', time.localtime(os.path.getmtime(path)))
        captures.append({'filename': f, 'date': date, 'size': size})

    # Apply filters
    filename_search = request.args.get('filename_search', '').lower()
    date_search = request.args.get('date_search', '')
    if filename_search:
        captures = [c for c in captures if filename_search in c['filename'].lower()]
    if date_search:
        captures = [c for c in captures if c['date'] == date_search]

    summary = {
        'total_captures': len(files),
        'total_size': f"{sum(os.path.getsize(os.path.join(captures_dir, f)) for f in files) // (1024*1024) if files else 0} MB",
        'last_saved': files[-1] if files else 'N/A'
    }
    return render_template('saved_captures.html', summary=summary, captures=captures)


# Settings persistence and validation
import json
import re
from backend.config import THRESHOLDS

SETTINGS_FILE = os.path.join(os.path.dirname(__file__), 'settings.json')

def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'r') as f:
            return json.load(f)
    return {
        'thresholds': THRESHOLDS.copy(),
        'notification_email': 'admin@example.com',
        'ml_model': 'isolation_forest'
    }

def save_settings(settings):
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(settings, f, indent=2)

def is_valid_email(email):
    return re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email)

def get_ml_model_status():
    settings_state = load_settings()
    choice = settings_state.get('ml_model', 'isolation_forest')
    base_dir = os.path.join(os.path.dirname(__file__), 'data', 'models')
    path_map = {
        'isolation_forest': os.path.join(base_dir, 'attack_predictor.pkl'),
        'random_forest': os.path.join(base_dir, 'attack_predictor_rf.pkl'),
        'svm': os.path.join(base_dir, 'attack_predictor_svm.pkl'),
    }
    model_path = path_map.get(choice, path_map['isolation_forest'])
    status = 'Trained' if os.path.exists(model_path) else 'Not trained'
    return f"{choice.replace('_',' ').title()}: {status}"

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    settings_state = load_settings()
    error_msgs = []
    if request.method == 'POST':
        if 'restore_defaults' in request.form:
            # Restore default settings
            settings_state = {
                'thresholds': THRESHOLDS.copy(),
                'notification_email': 'admin@example.com',
                'ml_model': 'isolation_forest'
            }
            save_settings(settings_state)
            flash('Settings restored to defaults.', 'success')
        elif 'upload_model' in request.form:
            # Handle ML model upload
            model_file = request.files.get('model_file')
            if model_file and model_file.filename.endswith('.pkl'):
                model_dir = os.path.join(os.path.dirname(__file__), 'data/models')
                os.makedirs(model_dir, exist_ok=True)
                save_path = os.path.join(model_dir, secure_filename(model_file.filename))
                model_file.save(save_path)
                flash(f'ML model uploaded: {model_file.filename}', 'success')
            else:
                flash('Please upload a valid .pkl model file.', 'danger')
        elif 'retrain_model' in request.form:
            # Placeholder for retraining logic
            flash('Retraining ML model... (not implemented)', 'info')
        else:
            # Validate and update thresholds (DoS/DDoS only)
            for key in ['ddos_packet_count']:
                value = request.form.get(key, settings_state['thresholds'][key])
                try:
                    value = int(value)
                    if value < 1:
                        error_msgs.append(f"{key.replace('_', ' ').title()} must be a positive integer.")
                    else:
                        settings_state['thresholds'][key] = value
                except Exception:
                    error_msgs.append(f"{key.replace('_', ' ').title()} must be a valid integer.")
            # Validate email
            email = request.form.get('notification_email', settings_state['notification_email'])
            if not email:
                error_msgs.append("Notification email is required.")
            elif not is_valid_email(email):
                error_msgs.append("Notification email format is invalid.")
            else:
                settings_state['notification_email'] = email
            # Validate ML model selection
            ml_model = request.form.get('ml_model', settings_state['ml_model'])
            allowed_models = ['isolation_forest', 'random_forest', 'svm']
            if ml_model not in allowed_models:
                error_msgs.append(f"ML model must be one of: {', '.join(allowed_models)}.")
            else:
                settings_state['ml_model'] = ml_model
            if not error_msgs:
                save_settings(settings_state)
                flash('Settings updated successfully!', 'success')
            else:
                for msg in error_msgs:
                    flash(msg, 'danger')

    return render_template(
        'settings.html',
        thresholds=settings_state['thresholds'],
        ml_model_status=get_ml_model_status(),
        notification_email=settings_state['notification_email'],
        ml_model=settings_state['ml_model']
    )

@app.route('/ai-assistant')
def ai_assistant():
    return render_template('ai_assistant.html')

# Secure file download route
@app.route('/download/<path:filename>')
def download_capture(filename):
    captures_dir = app.config['UPLOAD_FOLDER']
    safe_filename = secure_filename(filename)
    # Prevent directory traversal
    if '/' in safe_filename or '\\' in safe_filename or not safe_filename.endswith('.pcap'):
        flash('Invalid file name.', 'danger')
        logging.warning(f"Rejected download: suspicious filename {filename}")
        return redirect(url_for('saved_captures'))
    # Only allow download of known files
    allowed_files = set(f for f in os.listdir(captures_dir) if f.endswith('.pcap'))
    if safe_filename not in allowed_files:
        flash('File not found.', 'danger')
        logging.warning(f"Rejected download: file not found {safe_filename}")
        return redirect(url_for('saved_captures'))
    return send_from_directory(captures_dir, safe_filename, as_attachment=True)

# Delete capture from UI form
@app.route('/delete_capture/<path:filename>', methods=['POST'])
def delete_capture(filename):
    captures_dir = app.config['UPLOAD_FOLDER']
    safe_filename = secure_filename(filename)
    if '/' in safe_filename or '\\' in safe_filename or not safe_filename.endswith('.pcap'):
        flash('Invalid file name.', 'danger')
        logging.warning(f"Rejected delete: suspicious filename {filename}")
        return redirect(url_for('saved_captures'))
    allowed_files = set(f for f in os.listdir(captures_dir) if f.endswith('.pcap'))
    if safe_filename not in allowed_files:
        flash('File not found.', 'danger')
        logging.warning(f"Rejected delete: file not found {safe_filename}")
        return redirect(url_for('saved_captures'))
    try:
        os.remove(os.path.join(captures_dir, safe_filename))
        flash(f'Deleted {safe_filename}', 'success')
    except Exception as e:
        logging.error(f"Error deleting {safe_filename}: {e}")
        flash(f'Error deleting {safe_filename}: {e}', 'danger')
    return redirect(url_for('saved_captures'))


# Dashboard API endpoints
@app.route('/api/dashboard-metrics')
def api_dashboard_metrics():
    history = load_analysis_history()
    packets_captured = sum(entry.get('total_packets', 0) for entry in history)
    threats_detected = sum(len(entry.get('alerts', [])) for entry in history)
    ml_anomalies = sum(len([p for p in entry.get('ml_predictions', []) if 'Anomaly' in p or 'Attack' in p]) for entry in history)
    security_status = "High Threat" if ml_anomalies > 0 else "Normal"
    return jsonify({
        'packets_captured': packets_captured,
        'threats_detected': threats_detected,
        'ml_anomalies': ml_anomalies,
        'security_status': security_status
    })

@app.route('/api/dashboard-history')
def api_dashboard_history():
    history = load_analysis_history()
    recent_history = history[-10:] if history else []
    return jsonify(recent_history)

# Packet Analysis API endpoints
@app.route('/api/packet-analysis-summary')
def api_packet_analysis_summary():
    history = load_analysis_history()
    total_packets = sum(entry.get('total_packets', 0) for entry in history)
    threats_detected = sum(len(entry.get('alerts', [])) for entry in history)
    ml_anomalies = sum(len([p for p in entry.get('ml_predictions', []) if 'Anomaly' in p or 'Attack' in p]) for entry in history)
    protocols = ', '.join(set(proto for entry in history for proto in entry.get('protocol_counts', {}).keys()))
    return jsonify({
        'total_packets': total_packets,
        'threats_detected': threats_detected,
        'ml_anomalies': ml_anomalies,
        'protocols': protocols
    })

@app.route('/api/packet-analysis-protocols')
def api_packet_analysis_protocols():
    history = load_analysis_history()
    from collections import Counter
    protocol_counts = Counter()
    for entry in history:
        for proto, count in entry.get('protocol_counts', {}).items():
            protocol_counts[proto] += count
    return jsonify(protocol_counts)

@app.route('/api/packet-analysis-packets')
def api_packet_analysis_packets():
    history = load_analysis_history()
    rows = []
    for entry in history:
        ts = entry.get('timestamp', '')
        proto_hint = next(iter(entry.get('protocol_counts', {}).keys()), 'N/A')
        alerts = entry.get('alerts', [])
        if alerts:
            for alert in alerts:
                m = re.search(r'from ([\d\.]+)', alert)
                src_ip = m.group(1) if m else 'Unknown'
                rows.append({
                    'timestamp': ts,
                    'src_ip': src_ip,
                    'dst_ip': 'N/A',
                    'protocol': proto_hint,
                    'packet_size': entry.get('total_packets', 0),
                    'threat': True
                })
        else:
            rows.append({
                'timestamp': ts,
                'src_ip': 'N/A',
                'dst_ip': 'N/A',
                'protocol': proto_hint,
                'packet_size': entry.get('total_packets', 0),
                'threat': False
            })
    return jsonify(rows)

# Saved Captures API endpoints
@app.route('/api/saved-captures-summary')
def api_saved_captures_summary():
    captures_dir = app.config['UPLOAD_FOLDER']
    files = [f for f in os.listdir(captures_dir) if f.endswith('.pcap')] if os.path.exists(captures_dir) else []
    total_captures = len(files)
    total_size = f"{sum(os.path.getsize(os.path.join(captures_dir, f)) for f in files) // (1024*1024)} MB" if files else "0 MB"
    last_saved = files[-1] if files else 'N/A'
    return jsonify({'total_captures': total_captures, 'total_size': total_size, 'last_saved': last_saved})

@app.route('/api/saved-captures-list')
def api_saved_captures_list():
    captures_dir = app.config['UPLOAD_FOLDER']
    files = [f for f in os.listdir(captures_dir) if f.endswith('.pcap')] if os.path.exists(captures_dir) else []
    captures = []
    for f in files:
        path = os.path.join(captures_dir, f)
        size = f"{os.path.getsize(path) // 1024} KB"
        date = time.strftime('%Y-%m-%d', time.localtime(os.path.getmtime(path)))
        captures.append({'filename': f, 'date': date, 'size': size})
    return jsonify(captures)

@app.route('/api/download-capture')
def api_download_capture():
    filename = request.args.get('filename')
    captures_dir = app.config['UPLOAD_FOLDER']
    safe_filename = secure_filename(filename)
    if '/' in safe_filename or '\\' in safe_filename or not safe_filename.endswith('.pcap'):
        return jsonify({'error': 'Invalid file name.'}), 400
    allowed_files = set(f for f in os.listdir(captures_dir) if f.endswith('.pcap'))
    if safe_filename not in allowed_files:
        return jsonify({'error': 'File not found.'}), 404
    return send_from_directory(captures_dir, safe_filename, as_attachment=True)

@app.route('/api/delete-capture', methods=['POST'])
def api_delete_capture():
    data = request.get_json()
    filename = data.get('filename')
    captures_dir = app.config['UPLOAD_FOLDER']
    safe_filename = secure_filename(filename)
    path = os.path.join(captures_dir, safe_filename)
    if os.path.exists(path):
        os.remove(path)
        return jsonify({'success': True})
    return jsonify({'error': 'File not found.'}), 404

# ML Predictions API endpoints
@app.route('/api/ml-predictions-summary')
def api_ml_predictions_summary():
    history = load_analysis_history()
    anomaly_counts = {'Anomaly': 0, 'Normal': 0}
    last_scan_time = 'N/A'
    for entry in history:
        last_scan_time = entry.get('timestamp', last_scan_time)
        for p in entry.get('ml_predictions', []):
            if 'Anomaly' in p or 'Attack' in p:
                anomaly_counts['Anomaly'] += 1
            else:
                anomaly_counts['Normal'] += 1
    return jsonify({'anomaly_counts': anomaly_counts, 'last_scan_time': last_scan_time})

@app.route('/api/ml-predictions-list')
def api_ml_predictions_list():
    history = load_analysis_history()
    rows = []
    for entry in history:
        for p in entry.get('ml_predictions', []):
            label = 'Anomaly' if ('Anomaly' in p or 'Attack' in p) else 'Normal'
            m = re.search(r'from ([\d\.]+)', p)
            src_ip = m.group(1) if m else 'Unknown'
            rows.append({
                'timestamp': entry.get('timestamp', ''),
                'src_ip': src_ip,
                'dst_ip': 'N/A',
                'protocol': 'N/A',
                'label': label,
                'confidence': 1.0 if label == 'Anomaly' else 0.5
            })
    return jsonify(rows)

# Settings API endpoints
@app.route('/api/settings', methods=['GET', 'POST'])
def api_settings():
    if request.method == 'GET':
        return jsonify(load_settings())
    else:
        settings = request.get_json()
        save_settings(settings)
        return jsonify({'success': True})

# Authentication API endpoints (placeholders)
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    # TODO: Implement real authentication
    if username == 'admin' and password == 'admin':
        return jsonify({'success': True, 'token': 'demo-token'})
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/clear-analysis-history', methods=['POST'])
@csrf.exempt
def clear_analysis_history():
    save_analysis_history([])
    return jsonify({'status': 'cleared'})

if __name__ == '__main__':
    print("Starting Flask app...")
    app.run(host='0.0.0.0', port=5000, debug=False)
