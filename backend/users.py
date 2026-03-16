import hashlib
import json
import os

# Path to persistent user storage
USERS_FILE = os.path.join(os.path.dirname(__file__), '../users.json')

def load_users():
    """Load users from JSON file."""
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_users(users_dict):
    """Save users to JSON file."""
    with open(USERS_FILE, 'w') as f:
        json.dump(users_dict, f, indent=2)

# Load users from file, or use default
USERS = load_users()
if not USERS:
    # Default admin user
    USERS = {
        'admin': hashlib.sha256('admin123'.encode()).hexdigest(),
    }
    save_users(USERS)

def verify_user(username, password):
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return USERS.get(username) == hashed

def add_user(username, password):
    USERS[username] = hashlib.sha256(password.encode()).hexdigest()
    save_users(USERS)
