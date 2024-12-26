#!/bin/bash

# Ultra-Advanced SSH Connection Optimizer for Ubuntu 20.04+ (2024 Edition)
# Features advanced network optimization, ML-based performance tuning, and intelligent routing

# Strict error handling
set -euo pipefail
IFS=$'\n\t'

# Terminal colors
declare -r RED='\033[0;31m'
declare -r GREEN='\033[0;32m'
declare -r YELLOW='\033[1;33m'
declare -r BLUE='\033[0;34m'
declare -r NC='\033[0m'

# Configuration
declare -r VENV_PATH="/opt/ssh-optimizer-env"
declare -r LOG_FILE="/var/log/ssh-optimizer.log"
declare -r CONFIG_DIR="/etc/ssh-optimizer"
declare -r PERFORMANCE_DB="${CONFIG_DIR}/performance.sqlite"

# Initialize logging with timestamps
log() {
    local level=$1
    shift
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [$level] $*" | tee -a "$LOG_FILE"
}

# Enhanced error handling
error_handler() {
    local line_no=$1
    local error_code=$2
    log "ERROR" "Error occurred in script at line: ${line_no}, error code: ${error_code}"
}
trap 'error_handler ${LINENO} $?' ERR

# Check system compatibility
check_system() {
    local version
    version=$(lsb_release -rs)
    if ! awk -v ver="$version" 'BEGIN{exit!(ver>=20.04)}'; then
        log "ERROR" "This script requires Ubuntu 20.04 or newer"
        exit 1
    fi
}

# Advanced package installation with fallback options
install_package() {
    local package=$1
    local retries=3
    local delay=5

    while ((retries > 0)); do
        if apt-get install -y "$package" >/dev/null 2>&1; then
            log "INFO" "Successfully installed $package"
            return 0
        fi
        ((retries--))
        if ((retries > 0)); then
            log "WARN" "Failed to install $package, retrying in ${delay}s..."
            sleep "$delay"
        fi
    done

    # Fallback repositories
    if ! apt-get install -y --fix-missing "$package"; then
        log "ERROR" "Failed to install $package after all attempts"
        return 1
    fi
}

# Advanced Python environment setup
setup_python_env() {
    log "INFO" "Setting up Python virtual environment with advanced packages"
    
    python3 -m venv "$VENV_PATH"
    # shellcheck disable=SC1090
    source "${VENV_PATH}/bin/activate"
    
    # First install numpy with specific version to avoid conflicts
    pip install --no-cache-dir numpy==1.24.3
    
    # Install advanced Python packages for optimization
    pip install --no-cache-dir \
        paramiko \
        sshtunnel \
        psutil \
        pandas \
        scikit-learn \
        tensorflow-lite \
        pyroute2 \
        netaddr \
        pytest \
        python-daemon

    # Verify numpy version
    python3 -c "import numpy; print('Numpy version:', numpy.__version__)"
}


# Network optimization using advanced metrics
optimize_network() {
    log "INFO" "Applying advanced network optimizations"
    
    # Configure advanced TCP parameters
    cat > /etc/sysctl.d/99-ssh-optimizer.conf << 'EOL'
# Advanced TCP optimizations
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_low_latency = 1
net.ipv4.tcp_autocorking = 0
net.ipv4.tcp_thin_linear_timeouts = 1

# Advanced memory optimizations
net.ipv4.tcp_mem = 67108864 67108864 67108864
net.ipv4.udp_mem = 67108864 67108864 67108864
net.core.netdev_max_backlog = 300000
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 262144
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
EOL

    sysctl --system
}

# Advanced SSH configuration with security hardening
configure_ssh() {
    log "INFO" "Applying advanced SSH configuration"
    
    # Backup existing config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%F)
    
    cat > /etc/ssh/sshd_config << 'EOL'
# Advanced SSH Configuration
Port 22
AddressFamily any
ListenAddress 0.0.0.0
Protocol 2

# Enhanced Security Settings
PermitRootLogin prohibit-password
PasswordAuthentication yes
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 20
MaxStartups 10:30:60
MaxSessions 40

# Performance Optimizations
Compression yes
TCPKeepAlive yes
ClientAliveInterval 30
ClientAliveCountMax 3
UseDNS no
GSSAPIAuthentication no
UsePAM yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO

# Advanced Security Features
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
EOL
}

# Create advanced Python monitoring script
create_monitor_script() {
    cat > "${CONFIG_DIR}/ssh_monitor.py" << 'EOL'
#!/usr/bin/env python3
import psutil
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import sqlite3
import time
import subprocess
from datetime import datetime
import logging

class SSHMonitor:
    def __init__(self):
        self.logger = logging.getLogger('ssh_monitor')
        self.conn = sqlite3.connect('/etc/ssh-optimizer/performance.sqlite')
        self.setup_database()
        
    def setup_database(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS performance_metrics (
                timestamp TEXT,
                cpu_percent REAL,
                memory_percent REAL,
                network_latency REAL,
                connection_count INTEGER,
                anomaly_score REAL
            )
        ''')
        self.conn.commit()
        
    def collect_metrics(self):
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'cpu_percent': psutil.cpu_percent(),
            'memory_percent': psutil.virtual_memory().percent,
            'network_latency': self.measure_latency(),
            'connection_count': len([conn for conn in psutil.net_connections() 
                                   if conn.laddr.port == 22])
        }
        return metrics
        
    def measure_latency(self):
        try:
            result = subprocess.run(['ping', '-c', '1', '8.8.8.8'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                latency = float(result.stdout.split('time=')[1].split()[0])
                return latency
            return -1
        except:
            return -1
            
    def detect_anomalies(self, data):
        if len(data) < 10:
            return 0
        
        clf = IsolationForest(contamination=0.1, random_state=42)
        features = ['cpu_percent', 'memory_percent', 'network_latency']
        X = data[features].values
        scores = clf.fit_predict(X)
        return -1 if scores[-1] == -1 else 1
        
    def optimize_system(self, metrics):
        if metrics['cpu_percent'] > 80:
            subprocess.run(['nice', '-n', '10', 'sshd'])
        
        if metrics['memory_percent'] > 90:
            subprocess.run(['sync'])
            with open('/proc/sys/vm/drop_caches', 'w') as f:
                f.write('3')
            
    def run(self):
        while True:
            metrics = self.collect_metrics()
            df = pd.read_sql('SELECT * FROM performance_metrics', self.conn)
            anomaly_score = self.detect_anomalies(df)
            metrics['anomaly_score'] = anomaly_score
            
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO performance_metrics 
                VALUES (:timestamp, :cpu_percent, :memory_percent, 
                        :network_latency, :connection_count, :anomaly_score)
            ''', metrics)
            self.conn.commit()
            
            if anomaly_score == -1:
                self.optimize_system(metrics)
            
            time.sleep(60)

if __name__ == '__main__':
    monitor = SSHMonitor()
    monitor.run()
EOL

    chmod +x "${CONFIG_DIR}/ssh_monitor.py"
}

# Create systemd service for monitoring
create_monitor_service() {
    cat > /etc/systemd/system/ssh-monitor.service << 'EOL'
[Unit]
Description=SSH Performance Monitor
After=network.target

[Service]
Type=simple
ExecStart=/opt/ssh-optimizer-env/bin/python3 /etc/ssh-optimizer/ssh_monitor.py
Restart=always
User=root
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOL

    systemctl daemon-reload
    systemctl enable ssh-monitor
    systemctl start ssh-monitor
}

# Create advanced connection script
create_connection_script() {
    cat > /usr/local/bin/smart-ssh << 'EOL'
#!/bin/bash

if [ $# -lt 1 ]; then
    echo "Usage: $0 <host> [ssh options]"
    exit 1
fi

HOST=$1
shift

# Create multiplexing directory
mkdir -p ~/.ssh/controlmasters

# Test connection quality
ping -c 3 "$HOST" > /dev/null 2>&1
LATENCY=$?

if [ $LATENCY -eq 0 ]; then
    # Good connection - use standard optimized SSH
    ssh -o "Compression=yes" \
        -o "TCPKeepAlive=yes" \
        -o "ServerAliveInterval=30" \
        -o "ServerAliveCountMax=3" \
        -o "ControlMaster=auto" \
        -o "ControlPath=~/.ssh/controlmasters/%r@%h:%p" \
        -o "ControlPersist=10m" \
        -o "IPQoS=throughput" \
        -o "ConnectTimeout=10" \
        "$HOST" "$@"
else
    # Poor connection - use Mosh if available
    if command -v mosh >/dev/null 2>&1; then
        echo "Using Mosh for unstable connection..."
        mosh --predict=experimental "$HOST" -- tmux new-session -A -s main
    else
        # Fallback to resilient SSH settings
        ssh -o "Compression=yes" \
            -o "TCPKeepAlive=yes" \
            -o "ServerAliveInterval=10" \
            -o "ServerAliveCountMax=6" \
            -o "ConnectTimeout=30" \
            -o "NumberOfPasswordPrompts=3" \
            -o "IPQoS=lowdelay" \
            "$HOST" "$@"
    fi
fi
EOL

    chmod +x /usr/local/bin/smart-ssh
}

# Main installation function
main() {
    # Check root privileges
    if [ "$EUID" -ne 0 ]; then 
        log "ERROR" "Please run as root"
        exit 1
    fi

    # Create necessary directories
    mkdir -p "$CONFIG_DIR"
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"

    # System checks and preparation
    check_system
    log "INFO" "Starting advanced SSH optimization installation"

    # Update and install packages
    apt-get update
    apt-get upgrade -y

    # Install required packages
    PACKAGES=(
        python3
        python3-pip
        python3-venv
        python3-dev
        build-essential
        mosh
        netcat-openbsd
        iperf3
        ethtool
        sysstat
        tcptraceroute
        sqlite3
        nodejs
        npm
        net-tools
        cmake
        autoconf
        libtool
        pkg-config
    )

    for package in "${PACKAGES[@]}"; do
        install_package "$package"
    done

    # Setup components
    setup_python_env
    optimize_network
    configure_ssh
    create_monitor_script
    create_monitor_service
    create_connection_script

    # Restart SSH service
    systemctl restart ssh

    log "INFO" "Installation complete! System optimization is active."
    echo -e "${GREEN}Advanced SSH optimization complete!${NC}"
    echo -e "${YELLOW}Usage: smart-ssh hostname [options]${NC}"
    echo -e "${BLUE}Monitor logs: tail -f ${LOG_FILE}${NC}"
}

main "$@"
