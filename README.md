# SafeWeb IDS

## Overview
SafeWeb IDS is a Flask-based intrusion detection system with packet capture, ML-based analysis, user authentication, persistent settings, and REST API endpoints.

## Features
- Packet capture and analysis
- ML model management (upload, retrain, switch)
- User authentication (local, Google, GitHub)
- Persistent settings and analysis history
- REST API endpoints for integration
- Responsive, modern UI

## Setup
1. Clone the repository
2. Create and activate a Python virtual environment
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Set environment variables for OAuth (Google, GitHub)
5. Run the app:
   ```bash
   python flask_app.py
   ```

## Testing
Run unit tests with pytest:
```bash
pytest tests/
```

## API Endpoints
- `/api/analysis_history` (GET)
- `/api/settings` (GET)
- `/api/ml_model_status` (GET)

## Contributing
See CONTRIBUTING.md for guidelines.

## License
MIT
