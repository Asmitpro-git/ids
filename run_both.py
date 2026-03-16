import subprocess
import time

# Start Flask backend
backend = subprocess.Popen(['python', 'flask_app.py'])

# Wait a moment to ensure backend starts
time.sleep(2)

# Start frontend static server (serves files from ./frontend on port 8000)
frontend = subprocess.Popen(['python3', '-m', 'http.server', '8000', '--directory', 'frontend'])

try:
    # Wait for both processes to finish (they won't, unless killed)
    backend.wait()
    frontend.wait()
except KeyboardInterrupt:
    # Graceful shutdown on Ctrl+C
    backend.terminate()
    frontend.terminate()
