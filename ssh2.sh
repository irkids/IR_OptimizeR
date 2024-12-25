#!/bin/bash

# SSH Connection Optimizer for Ubuntu 24.04
# This script optimizes SSH connections using various techniques and tools
# Prerequisites will be automatically installed if missing

# Error handling
set -e

# Color coding for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check for root privileges
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root${NC}"
    exit 1
fi

echo -e "${GREEN}Starting SSH Connection Optimizer...${NC}"

# Install system prerequisites
echo -e "${YELLOW}Installing system prerequisites...${NC}"
apt-get update
apt-get install -y \
    python3-full \
    python3-venv \
    pipx \
    nodejs \
    npm \
    mosh \
    netcat \
    iperf3 \
    ethtool \
    sysstat \
    tcptraceroute \
    hping3 \
    python3-paramiko \
    python3-psutil \
    python3-numpy \
    python3-pandas

# Setup Python virtual environment
echo -e "${YELLOW}Setting up Python virtual environment...${NC}"
VENV_PATH="/opt/ssh-optimizer-env"
python3 -m venv "$VENV_PATH"

# Install Python packages in virtual environment
echo -e "${YELLOW}Installing Python packages in virtual environment...${NC}"
"$VENV_PATH/bin/pip" install \
    paramiko \
    sshtunnel \
    psutil \
    numpy \
    pandas

# Install Node.js packages
echo -e "${YELLOW}Installing Node.js packages...${NC}"
npm install -g \
    ssh2 \
    node-ssh \
    net-ping

# Backup existing SSH config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Optimize SSH configuration
cat >> /etc/ssh/sshd_config << 'EOL'
# Performance optimizations
Compression yes
TCPKeepAlive yes
ClientAliveInterval 60
ClientAliveCountMax 3
UseDNS no
GSSAPIAuthentication no
UsePAM yes

# Security settings
Protocol 2
PermitRootLogin prohibit-password
PasswordAuthentication no
X11Forwarding no
MaxStartups 10:30:100
MaxAuthTries 5
LoginGraceTime 30
EOL

# Optimize system network settings
cat >> /etc/sysctl.conf << 'EOL'
# TCP optimizations
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
EOL

# Apply sysctl changes
sysctl -p

# Create SSH optimization script
cat > /usr/local/bin/ssh-optimizer.py << 'EOL'
#!/opt/ssh-optimizer-env/bin/python3
import sys
import psutil
import numpy as np
import subprocess
from datetime import datetime

def optimize_connection(host):
    # Monitor current connection
    net_stats = psutil.net_connections()
    
    # Analyze network conditions
    subprocess.run(['iperf3', '-c', host])
    
    # Optimize MTU size
    subprocess.run(['ip', 'link', 'set', 'dev', 'eth0', 'mtu', '9000'])
    
    # Enable TCP BBR
    subprocess.run(['sysctl', 'net.ipv4.tcp_congestion_control=bbr'])
    
    # Log optimization results
    with open('/var/log/ssh-optimizer.log', 'a') as f:
        f.write(f"{datetime.now()} - Optimized connection to {host}\n")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        optimize_connection(sys.argv[1])
EOL

chmod +x /usr/local/bin/ssh-optimizer.py

# Create SSH connection wrapper script
cat > /usr/local/bin/smart-ssh << 'EOL'
#!/bin/bash

# Check if target host is provided
if [ $# -lt 1 ]; then
    echo "Usage: $0 <host> [ssh options]"
    exit 1
fi

HOST=$1
shift

# Run Python optimizer
/usr/local/bin/ssh-optimizer.py "$HOST"

# Test connection type
if command -v mosh-server >/dev/null 2>&1 && nc -z "$HOST" 60000-61000; then
    echo "Using Mosh for better performance..."
    mosh "$HOST" -- tmux new-session -A -s main
else
    echo "Using optimized SSH..."
    ssh -o "Compression=yes" \
        -o "TCPKeepAlive=yes" \
        -o "ServerAliveInterval=60" \
        -o "ServerAliveCountMax=3" \
        -o "ControlMaster=auto" \
        -o "ControlPath=~/.ssh/control-%h-%p-%r" \
        -o "ControlPersist=10m" \
        "$HOST" "$@"
fi
EOL

chmod +x /usr/local/bin/smart-ssh

# Create systemd service for connection monitoring
cat > /etc/systemd/system/ssh-monitor.service << 'EOL'
[Unit]
Description=SSH Connection Monitor
After=network.target

[Service]
ExecStart=/usr/bin/node /usr/local/bin/ssh-monitor.js
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOL

# Create Node.js monitoring script
cat > /usr/local/bin/ssh-monitor.js << 'EOL'
const ssh2 = require('ssh2');
const ping = require('net-ping');
const fs = require('fs');

const monitor = {
    checkConnection: async (host) => {
        const session = ping.createSession();
        return new Promise((resolve) => {
            session.pingHost(host, (error, target) => {
                resolve(!error);
            });
        });
    },
    
    logStatus: (host, status) => {
        fs.appendFileSync('/var/log/ssh-monitor.log',
            `${new Date().toISOString()} - ${host}: ${status}\n`);
    }
};

// Start monitoring
setInterval(() => {
    const hosts = fs.readFileSync('/etc/ssh/ssh_config')
        .toString()
        .match(/Host\s+([^\s]+)/g) || [];
    
    hosts.forEach(async (host) => {
        const status = await monitor.checkConnection(host);
        monitor.logStatus(host, status ? 'OK' : 'Failed');
    });
}, 300000); // Check every 5 minutes
EOL

# Enable and start monitoring service
systemctl daemon-reload
systemctl enable ssh-monitor
systemctl start ssh-monitor

# Final setup and permissions
chmod 600 /etc/ssh/sshd_config
systemctl restart sshd

echo -e "${GREEN}SSH optimization complete!${NC}"
echo -e "${YELLOW}Usage:${NC}"
echo -e "  smart-ssh hostname [ssh options]"
echo -e "${YELLOW}Logs:${NC}"
echo -e "  - SSH Optimizer: /var/log/ssh-optimizer.log"
echo -e "  - Connection Monitor: /var/log/ssh-monitor.log"
echo -e "${YELLOW}Note:${NC}"
echo -e "  - Python virtual environment is located at: ${VENV_PATH}"
echo -e "  - A system reboot is recommended to apply all optimizations"
