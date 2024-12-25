#!/bin/bash

# SSH Connection Optimizer for Ubuntu 24.04
# This script optimizes SSH connections using various techniques and tools

# Error handling
set -e

# Color coding for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Function to install packages with error handling
install_package() {
    local package=$1
    echo -e "${YELLOW}Installing $package...${NC}"
    if ! apt-get install -y "$package" >/dev/null 2>&1; then
        echo -e "${RED}Failed to install $package, trying alternatives...${NC}"
        case $package in
            "netcat")
                apt-get install -y netcat-openbsd
                ;;
            "python3-full")
                apt-get install -y python3
                ;;
            *)
                echo -e "${RED}No alternative found for $package${NC}"
                return 1
                ;;
        esac
    fi
}

# Check for root privileges
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root${NC}"
    exit 1
fi

echo -e "${GREEN}Starting SSH Connection Optimizer...${NC}"

# Update package lists
echo -e "${YELLOW}Updating package lists...${NC}"
apt-get update

# Install system prerequisites
echo -e "${YELLOW}Installing system prerequisites...${NC}"
PACKAGES=(
    "python3-full"
    "python3-venv"
    "pipx"
    "nodejs"
    "npm"
    "mosh"
    "netcat-openbsd"
    "iperf3"
    "ethtool"
    "sysstat"
    "tcptraceroute"
    "python3-paramiko"
    "python3-psutil"
    "python3-numpy"
    "python3-pandas"
)

for package in "${PACKAGES[@]}"; do
    install_package "$package"
done

# Setup Python virtual environment
echo -e "${YELLOW}Setting up Python virtual environment...${NC}"
VENV_PATH="/opt/ssh-optimizer-env"
if [ -d "$VENV_PATH" ]; then
    rm -rf "$VENV_PATH"
fi
python3 -m venv "$VENV_PATH"

# Install Python packages in virtual environment
echo -e "${YELLOW}Installing Python packages in virtual environment...${NC}"
"$VENV_PATH/bin/pip" install --no-cache-dir \
    paramiko \
    sshtunnel \
    psutil \
    numpy \
    pandas

# Install Node.js packages
echo -e "${YELLOW}Installing Node.js packages...${NC}"
if ! command -v npm &> /dev/null; then
    echo -e "${RED}npm not found. Installing nodejs and npm...${NC}"
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
fi

npm install -g \
    ssh2 \
    node-ssh \
    net-ping

# Backup existing SSH config
if [ -f /etc/ssh/sshd_config ]; then
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
fi

# Optimize SSH configuration
cat > /etc/ssh/sshd_config << 'EOL'
# Performance optimizations
Port 22
AddressFamily any
ListenAddress 0.0.0.0
Protocol 2

# Authentication
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
ChallengeResponseAuthentication no

# Performance settings
Compression yes
TCPKeepAlive yes
ClientAliveInterval 60
ClientAliveCountMax 3
UseDNS no
GSSAPIAuthentication no
UsePAM yes

# Security settings
X11Forwarding no
MaxStartups 10:30:100
MaxAuthTries 5
LoginGraceTime 30

# Logging
SyslogFacility AUTH
LogLevel INFO
EOL

# Optimize system network settings
cat > /etc/sysctl.d/99-ssh-optimize.conf << 'EOL'
# TCP optimizations
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_slow_start_after_idle = 0
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Enable BBR congestion control if available
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOL

# Apply sysctl changes
sysctl --system

# Create SSH optimization script
cat > /usr/local/bin/ssh-optimizer.py << 'EOL'
#!/opt/ssh-optimizer-env/bin/python3
import sys
import psutil
import subprocess
from datetime import datetime

def optimize_connection(host):
    try:
        # Monitor current connection
        net_stats = psutil.net_connections()
        
        # Analyze network conditions
        subprocess.run(['iperf3', '-c', host], capture_output=True)
        
        # Optimize MTU size
        interfaces = psutil.net_if_stats()
        for interface in interfaces:
            if interfaces[interface].isup:
                subprocess.run(['ip', 'link', 'set', 'dev', interface, 'mtu', '9000'])
        
        # Log optimization results
        with open('/var/log/ssh-optimizer.log', 'a') as f:
            f.write(f"{datetime.now()} - Optimized connection to {host}\n")
            
    except Exception as e:
        with open('/var/log/ssh-optimizer.log', 'a') as f:
            f.write(f"{datetime.now()} - Error optimizing {host}: {str(e)}\n")

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

# Create SSH control directory if it doesn't exist
mkdir -p ~/.ssh/controlmasters

# Run Python optimizer
/usr/local/bin/ssh-optimizer.py "$HOST"

# Test connection type
if command -v mosh-server >/dev/null 2>&1 && nc -z -w5 "$HOST" 60000-61000 2>/dev/null; then
    echo "Using Mosh for better performance..."
    mosh "$HOST" -- tmux new-session -A -s main
else
    echo "Using optimized SSH..."
    ssh -o "Compression=yes" \
        -o "TCPKeepAlive=yes" \
        -o "ServerAliveInterval=60" \
        -o "ServerAliveCountMax=3" \
        -o "ControlMaster=auto" \
        -o "ControlPath=~/.ssh/controlmasters/%r@%h:%p" \
        -o "ControlPersist=10m" \
        "$HOST" "$@"
fi
EOL

chmod +x /usr/local/bin/smart-ssh

# Create log files with proper permissions
touch /var/log/ssh-optimizer.log
chmod 644 /var/log/ssh-optimizer.log

# Final setup and permissions
chmod 600 /etc/ssh/sshd_config

# Detect and restart the correct SSH service
if systemctl list-unit-files | grep -q ssh.service; then
    echo -e "${YELLOW}Restarting ssh.service...${NC}"
    systemctl restart ssh.service
elif systemctl list-unit-files | grep -q sshd.service; then
    echo -e "${YELLOW}Restarting sshd.service...${NC}"
    systemctl restart sshd.service
else
    echo -e "${RED}SSH service not found. Attempting to install...${NC}"
    apt-get install -y openssh-server
    systemctl enable ssh.service
    systemctl restart ssh.service
fi

# Verify SSH service status
if systemctl is-active ssh.service >/dev/null 2>&1; then
    echo -e "${GREEN}SSH service is running.${NC}"
elif systemctl is-active sshd.service >/dev/null 2>&1; then
    echo -e "${GREEN}SSH service is running.${NC}"
else
    echo -e "${RED}Warning: SSH service is not running. Please check your SSH configuration.${NC}"
    echo -e "${YELLOW}You can manually start it with: sudo systemctl start ssh.service${NC}"
fi

echo -e "${GREEN}SSH optimization complete!${NC}"
echo -e "${YELLOW}Usage:${NC}"
echo -e "  smart-ssh hostname [ssh options]"
echo -e "${YELLOW}Logs:${NC}"
echo -e "  - SSH Optimizer: /var/log/ssh-optimizer.log"
echo -e "${YELLOW}Note:${NC}"
echo -e "  - Python virtual environment is located at: ${VENV_PATH}"
echo -e "  - A system reboot is recommended to apply all optimizations"

# Check if SSH is accessible
if ! ss -tlnp | grep -q ':22'; then
    echo -e "${RED}Warning: SSH port (22) is not listening. You may need to:${NC}"
    echo -e "1. Check if SSH server is installed: ${YELLOW}sudo apt-get install openssh-server${NC}"
    echo -e "2. Start SSH service: ${YELLOW}sudo systemctl start ssh${NC}"
    echo -e "3. Enable SSH service: ${YELLOW}sudo systemctl enable ssh${NC}"
fi
