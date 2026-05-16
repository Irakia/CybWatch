#!/bin/bash

# Cybwatch Service Installer
# Generates and installs services

set -e

# get current user and directory
USER=$(whoami)
INSTALL_DIR=$(pwd)

echo "  Cybwatch Service Installer"
echo "================================"
echo ""
echo "User: $USER"
echo "Directory: $INSTALL_DIR"
echo ""

# check if in the right directory
if [ ! -f "src/main.py" ]; then
    echo "Error: Run this from the cybwatch directory"
    echo "  cd ~/cybwatch"
    echo "  ./setup/install-services.sh"
    exit 1
fi

# check venv exists
if [ ! -d "venv" ]; then
    echo "Error: Virtual environment not found"
    echo "  python3 -m venv venv"
    echo "  source venv/bin/activate"
    echo "  pip install -r requirements.txt"
    exit 1
fi

echo "Generating service files..."

# generate web service
cat > /tmp/cybwatch-web.service << EOF
[Unit]
Description=Cybwatch Web Dashboard
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin"
ExecStart=$INSTALL_DIR/venv/bin/uvicorn src.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# generate worker service
cat > /tmp/cybwatch-worker.service << EOF
[Unit]
Description=Cybwatch Background Worker
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin"
ExecStart=$INSTALL_DIR/venv/bin/python -m src.worker
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

echo "Installing services..."

# copy to systemd
sudo cp /tmp/cybwatch-web.service /etc/systemd/system/
sudo cp /tmp/cybwatch-worker.service /etc/systemd/system/

# cleanup
rm /tmp/cybwatch-web.service
rm /tmp/cybwatch-worker.service

# relod systemd
sudo systemctl daemon-reload

# enable services
sudo systemctl enable cybwatch-web
sudo systemctl enable cybwatch-worker

echo ""
echo "  Installation Complete!"
echo "================================"
echo ""
echo "Start services:"
echo "  sudo systemctl start cybwatch-web"
echo "  sudo systemctl start cybwatch-worker"
echo ""
echo "Check status:"
echo "  sudo systemctl status cybwatch-web"
echo "  sudo systemctl status cybwatch-worker"
echo ""
echo "View logs:"
echo "  journalctl -u cybwatch-web -f"
echo "  journalctl -u cybwatch-worker -f"
echo ""