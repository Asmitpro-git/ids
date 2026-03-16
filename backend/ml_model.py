
"""
Machine learning utilities for anomaly detection in network traffic.
Adds support for both Isolation Forest (unsupervised) and Random Forest (supervised).
"""
import os
import json
import logging
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib
from .packet_capture import extract_features  # Relative import (as fixed previously)

SETTINGS_FILE = os.path.join(os.path.dirname(__file__), 'settings.json')
MODELS_DIR = os.path.join(os.path.dirname(__file__), 'data', 'models')
ISO_MODEL_PATH = os.path.join(MODELS_DIR, 'attack_predictor.pkl')
RF_MODEL_PATH = os.path.join(MODELS_DIR, 'attack_predictor_rf.pkl')

logging.basicConfig(level=logging.INFO)

def preprocess_nsl_kdd(file_path='data/NSL-KDD/KDDTrain+.csv'):
    """Load and preprocess NSL-KDD dataset for both supervised and unsupervised flows."""
    try:
        # Define column names (from NSL-KDD documentation)
        columns = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
            'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
            'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
            'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
            'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
            'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
        ]
        # Read dataset
        if file_path.endswith('.txt'):
            df = pd.read_csv(file_path, names=columns, header=None)
        else:
            df = pd.read_csv(file_path)
    # Encode categorical columns
    le = LabelEncoder()
    df['protocol_type'] = le.fit_transform(df['protocol_type'])

    # Binary label for supervised training (1 = attack, 0 = normal)
    df['label_bin'] = (df['label'].str.lower() != 'normal').astype(int)

    # Select features for training/inference
    selected_features = ['protocol_type', 'src_bytes', 'dst_bytes', 'label_bin']
    df = df[selected_features].dropna()
    return df
    except FileNotFoundError:
        logging.error(f"Error: Dataset file {file_path} not found. Please download NSL-KDD.")
        return pd.DataFrame()
    except Exception as e:
        logging.error(f"Error preprocessing dataset: {e}")
        return pd.DataFrame()

def train_model(sample_data_df, algo="isolation_forest"):
    """Train anomaly detection model (Isolation Forest) or supervised detector (Random Forest)."""
    if sample_data_df.empty:
        logging.error("Error: Empty dataset provided. Cannot train model.")
        return None

    os.makedirs(MODELS_DIR, exist_ok=True)

    if algo == "random_forest":
        if 'label_bin' not in sample_data_df.columns:
            logging.error("Random Forest training requires a 'label_bin' column (0=normal, 1=attack).")
            return None
        X = sample_data_df.drop(columns=['label_bin'])
        y = sample_data_df['label_bin']
        model = RandomForestClassifier(
            n_estimators=200,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )
        model.fit(X, y)
        joblib.dump(model, RF_MODEL_PATH)
        logging.info(f"Random Forest trained and saved to {RF_MODEL_PATH}")
        return model

    # Default: Isolation Forest (unsupervised)
    X = sample_data_df.drop(columns=['label_bin']) if 'label_bin' in sample_data_df.columns else sample_data_df
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X)
    joblib.dump(model, ISO_MODEL_PATH)
    logging.info(f"Isolation Forest trained and saved to {ISO_MODEL_PATH}")
    return model


def _load_selected_model_name(model_name=None):
    """Resolve model choice from argument or settings.json."""
    if model_name:
        return model_name
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, 'r') as f:
                return json.load(f).get('ml_model', 'isolation_forest')
        except Exception:
            return 'isolation_forest'
    return 'isolation_forest'


def _align_features(features_df):
    """Align live features to training schema: ['protocol_type', 'src_bytes', 'dst_bytes']."""
    aligned_df = pd.DataFrame()

    # Map 'protocol' to 'protocol_type' (encode to numeric)
    if 'protocol' in features_df.columns:
        le = LabelEncoder()
        aligned_df['protocol_type'] = le.fit_transform(features_df['protocol'])
    else:
        aligned_df['protocol_type'] = 0  # Fallback if no protocol column

    # Map 'packet_size' to 'src_bytes' and 'dst_bytes' (approximation)
    if 'packet_size' in features_df.columns:
        aligned_df['src_bytes'] = features_df['packet_size']
        aligned_df['dst_bytes'] = features_df['packet_size']  # Symmetric approximation
    else:
        aligned_df['src_bytes'] = 0
        aligned_df['dst_bytes'] = 0  # Fallback

    # Ensure ordering
    return aligned_df[['protocol_type', 'src_bytes', 'dst_bytes']]

def predict_attacks(features_df, model=None, model_name=None):
    """Predict attacks using the selected ML model (Isolation Forest or Random Forest)."""
    if features_df.empty:
        return ["No packets to analyze"]

    choice = _load_selected_model_name(model_name)
    aligned_df = _align_features(features_df)

    try:
        if choice == 'random_forest':
            if model is None:
                if not os.path.exists(RF_MODEL_PATH):
                    return ["Random Forest model not trained. Please train first."]
                model = joblib.load(RF_MODEL_PATH)
            preds = model.predict(aligned_df)
            # If probabilities are available, append confidence
            if hasattr(model, 'predict_proba'):
                probs = model.predict_proba(aligned_df)[:, 1]
                return [f"Attack (p={p:.2f})" if lbl == 1 else f"Normal (p={1-p:.2f})" for lbl, p in zip(preds, probs)]
            return ["Attack" if lbl == 1 else "Normal" for lbl in preds]

        # Default / Isolation Forest path
        if model is None:
            if not os.path.exists(ISO_MODEL_PATH):
                return ["Isolation Forest model not trained. Please train first."]
            model = joblib.load(ISO_MODEL_PATH)
        preds = model.predict(aligned_df)
        return ["Anomaly (Potential Attack)" if pred == -1 else "Normal" for pred in preds]
    except Exception as e:
        logging.error(f"Prediction error: {e}")
        return ["Prediction failed due to feature mismatch or other error"]

if __name__ == "__main__":
    # Train model when script is run directly
    df = preprocess_nsl_kdd('data/NSL-KDD/KDDTrain+.txt')  # Use .txt or .csv
    if not df.empty:
        # Train both models for convenience when run directly
        train_model(df, algo="isolation_forest")
        train_model(df, algo="random_forest")