#!/bin/bash

# SafeWeb IDS Startup Script

echo "==================================="
echo "   SafeWeb IDS Starting..."
echo "==================================="
echo ""

# Check if running as root
if [ "$EUID" != "0" ]; then 
    echo "⚠️  WARNING: Not running as root!"
    echo "   Packet capture will not work without sudo privileges."
    echo "   Please run: sudo $0"
    echo ""
fi

# Activate virtual environment if it exists
if [ -d "env" ]; then
    echo "✓ Activating virtual environment..."
    source env/bin/activate
fi

# Check Python version
PYTHON_VERSION=$(python --version 2>&1 | awk '{print $2}')
echo "✓ Python version: $PYTHON_VERSION"

# Check if required packages are installed
echo "✓ Checking dependencies..."
python -c "import flask, scapy, pandas" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "⚠️  Missing dependencies. Installing..."
    pip install -r requirements.txt
fi

# Check network interfaces
echo ""
echo "Available network interfaces:"
python -c "from backend.packet_capture import get_if_list; print('  - ' + '\n  - '.join(get_if_list()))"

echo ""
echo "==================================="
echo "   Starting Flask Application"
echo "==================================="
echo ""
echo "Access the IDS at: http://localhost:5000"
echo "Default credentials:"
echo "  Username: admin"
echo "  Password: admin123"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Start Flask app
python flask_app.py
