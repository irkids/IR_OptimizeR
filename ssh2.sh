#!/bin/bash

# Ultra-Advanced SSH Connection Optimizer for Ubuntu (2024 Edition)
# Features advanced network optimization, ML-based performance tuning, and intelligent routing
# Version 2.0 with dynamic version detection and enhanced DNS configuration

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
declare -r DNS_CONFIG="/etc/systemd/resolved.conf"

# Initialize logging with timestamps
log() {
    local level=$1
    shift
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [$level] $*" | tee -a "$LOG_FILE"
}

# Enhanced error handling with detailed logging
error_handler() {
    local line_no=$1
    local error_code=$2
    log "ERROR" "Error occurred in script at line: ${line_no}, error code: ${error_code}"
    log "ERROR" "Command that failed: $(sed -n "${line_no}p" "$0")"
    log "ERROR" "Stack trace:"
    local frame=0
    while caller $frame; do
        ((frame++))
    done | awk '{print "[ERROR] Called from line " $1 " in function " $2}'
}
trap 'error_handler ${LINENO} $?' ERR

# Dynamic version detection and package selection
get_ubuntu_version() {
    local version
    version=$(lsb_release -rs)
    echo "$version"
}

# Check system compatibility with detailed feedback
check_system() {
    local version
    version=$(get_ubuntu_version)
    log "INFO" "Detected Ubuntu version: $version"
    
    if ! awk -v ver="$version" 'BEGIN{exit!(ver>=18.04)}'; then
        log "ERROR" "This script requires Ubuntu 18.04 or newer"
        exit 1
    fi
    
    # CPU architecture check
    local arch
    arch=$(uname -m)
    log "INFO" "Detected architecture: $arch"
    
    # Memory check
    local mem_total
    mem_total=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
    if [ "$mem_total" -lt 1048576 ]; then  # Less than 1GB
        log "WARN" "System has less than 1GB RAM. Performance may be impacted."
    fi
}

# Advanced package installation with fallback options and version checks
install_package() {
    local package=$1
    local retries=3
    local delay=5
    local ubuntu_version
    ubuntu_version=$(get_ubuntu_version)

    # Package version mapping based on Ubuntu version
    case $package in
        "python3")
            if [ "$(echo "$ubuntu_version >= 22.04" | bc)" -eq 1 ]; then
                package="python3.10"
            elif [ "$(echo "$ubuntu_version >= 20.04" | bc)" -eq 1 ]; then
                package="python3.8"
            else
                package="python3.6"
            fi
            ;;
        "tensorflow-lite")
            if [ "$(echo "$ubuntu_version >= 20.04" | bc)" -eq 1 ]; then
                package="tflite-runtime"
            fi
            ;;
    esac

    while ((retries > 0)); do
        if apt-get install -y "$package" >/dev/null 2>&1; then
            log "INFO" "Successfully installed $package"
            return 0
        fi
        ((retries--))
        if ((retries > 0)); then
            log "WARN" "Failed to install $package, retrying in ${delay}s..."
            sleep "$delay"
            
            # Try updating package lists before retry
            apt-get update
        fi
    done

    # Advanced fallback handling
    log "WARN" "Attempting alternative installation methods for $package"
    
    # Package-specific fallback methods
    case $package in
        "python3"|"python3.8"|"python3.10")
            add-apt-repository -y ppa:deadsnakes/ppa && apt-get update
            ;;
        "tflite-runtime")
            pip3 install --no-cache-dir tflite-runtime
            return 0
            ;;
    esac

    # Final attempt with fix-missing
    if ! apt-get install -y --fix-missing "$package"; then
        log "ERROR" "Failed to install $package after all attempts"
        return 1
    fi
}

# Configure DNS settings with automatic optimization
configure_dns() {
    log "INFO" "Configuring optimized DNS settings"
    
    # Backup existing resolv.conf
    cp /etc/resolv.conf /etc/resolv.conf.backup.$(date +%F)
    
    # Configure systemd-resolved with optimized settings
    cat > "$DNS_CONFIG" << 'EOL'
[Resolve]
DNS=1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4
FallbackDNS=9.9.9.9 149.112.112.112
DNSSEC=allow-downgrade
DNSOverTLS=opportunistic
Cache=yes
DNSStubListener=yes
ReadEtcHosts=yes
EOL

    # Restart systemd-resolved
    systemctl restart systemd-resolved
    
    # Verify DNS configuration
    if dig +short google.com >/dev/null; then
        log "INFO" "DNS configuration successful"
    else
        log "WARN" "DNS configuration might have issues, falling back to defaults"
        mv /etc/resolv.conf.backup.$(date +%F) /etc/resolv.conf
    fi
}

# Advanced Python environment setup with version-specific packages
setup_python_env() {
    log "INFO" "Setting up Python virtual environment with advanced packages"
    
    # Remove existing venv if present
    rm -rf "$VENV_PATH"
    
    # Create new virtual environment
    python3 -m venv "$VENV_PATH"
    # shellcheck disable=SC1090
    source "${VENV_PATH}/bin/activate"
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install advanced Python packages for optimization
    declare -a packages=(
        "paramiko"
        "sshtunnel"
        "psutil"
        "numpy"
        "pandas"
        "scikit-learn"
        "pyroute2"
        "netaddr"
        "pytest"
        "python-daemon"
    )
    
    # Install packages with error handling
    for package in "${packages[@]}"; do
        if ! pip install --no-cache-dir "$package"; then
            log "ERROR" "Failed to install Python package: $package"
            continue
        fi
    done
    
    # Special handling for tensorflow-lite
    if ! pip install --no-cache-dir tflite-runtime; then
        log "WARN" "Could not install tflite-runtime, continuing without ML capabilities"
    fi
}

# Network optimization using advanced metrics and dynamic tuning
optimize_network() {
    log "INFO" "Applying advanced network optimizations"
    
    # Get system memory for dynamic tuning
    local mem_total
    mem_total=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
    local max_wmem=$((mem_total * 1024 / 4))  # Use up to 25% of total memory
    
    # Get network interface speed with proper error handling
    local interface
    interface=$(ip route | awk '/default/ {print $5}' | head -n1)
    if [[ -z "$interface" ]]; then
        log "WARN" "Could not determine network interface, using defaults"
        interface="eth0"
    fi
    
    local interface_speed
    interface_speed=$(ethtool "$interface" 2>/dev/null | awk '/Speed:/ {print $2}' | sed 's/Mb\/s//' || echo "1000")
    
    # Ensure interface_speed is set and numeric
    if ! [[ "$interface_speed" =~ ^[0-9]+$ ]]; then
        log "WARN" "Could not determine interface speed, using default of 1000 Mbps"
        interface_speed=1000
    fi
    
    # Dynamic buffer calculation based on network speed
    local optimal_buffer=$((interface_speed * 1024 * 128))  # 128KB per Mb/s
    
    # Configure advanced TCP parameters with dynamic values
    cat > /etc/sysctl.d/99-ssh-optimizer.conf << EOL
# Advanced TCP optimizations
net.core.rmem_max = ${optimal_buffer}
net.core.wmem_max = ${optimal_buffer}
net.ipv4.tcp_rmem = 4096 87380 ${optimal_buffer}
net.ipv4.tcp_wmem = 4096 65536 ${optimal_buffer}
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_congestion_control = bbr2
net.core.default_qdisc = fq_pie
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_low_latency = 1
net.ipv4.tcp_autocorking = 0
net.ipv4.tcp_thin_linear_timeouts = 1

# Dynamic memory optimizations
net.ipv4.tcp_mem = ${max_wmem} ${max_wmem} ${max_wmem}
net.ipv4.udp_mem = ${max_wmem} ${max_wmem} ${max_wmem}
net.core.netdev_max_backlog = 300000
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 262144
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1

# Additional optimizations for high-speed networks
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.core.optmem_max = 65536
net.ipv4.tcp_rfc1337 = 1
EOL

    # Apply sysctl settings
    if ! sysctl --system; then
        log "ERROR" "Failed to apply sysctl settings"
        return 1
    fi
    
    # Configure network interface optimizations
    if [ -n "$interface" ]; then
        ethtool -K "$interface" tso on gso on gro on 2>/dev/null || true
        ethtool -G "$interface" rx 4096 tx 4096 2>/dev/null || true
    fi
}

# Advanced SSH configuration with security hardening and version-specific settings
configure_ssh() {
    log "INFO" "Applying advanced SSH configuration"
    
    local ubuntu_version
    ubuntu_version=$(get_ubuntu_version)
    
    # Backup existing config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%F)
    
    # Determine optimal SSH security settings based on Ubuntu version
    local kex_algorithms="curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384"
    local ciphers="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com"
    local macs="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"
    
    # Add newer algorithms for newer Ubuntu versions
    if [ "$(echo "$ubuntu_version >= 20.04" | bc)" -eq 1 ]; then
        kex_algorithms+=",curve25519-sha256,curve25519-sha256@libssh.org"
        ciphers+=",aes256-gcm@openssh.com,chacha20-poly1305@openssh.com"
    fi
    
    cat > /etc/ssh/sshd_config << EOL
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
KexAlgorithms ${kex_algorithms}
Ciphers ${ciphers}
MACs ${macs}

# Additional hardening
X11Forwarding no
AllowAgentForwarding yes
AllowTcpForwarding yes
PrintLastLog yes
IgnoreRhosts yes
HostbasedAuthentication no
StrictModes yes
EOL

    # Test configuration
    if ! sshd -t; then
        log "ERROR" "SSH configuration test failed"
        mv /etc/ssh/sshd_config.backup.$(date +%F) /etc/ssh/sshd_config
        return 1
    fi
}

# Create advanced Python monitoring script with enhanced metrics
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
import os
import signal
import sys
from pathlib import Path

class SSHMonitor:
    def __init__(self):
        self.setup_logging()
        self.conn = self.setup_database()
        self.running = True
        signal.signal(signal.SIGTERM, self.handle_shutdown)
        signal.signal(signal.SIGINT, self.handle_shutdown)
        
    def setup_logging(self):
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler('/var/log/ssh-optimizer.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('ssh_monitor')
        
    def setup_database(self):
        db_path = Path('/etc/ssh-optimizer/performance.sqlite')
        db_path.parent.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS performance_metrics (
                timestamp TEXT,
                cpu_percent REAL,
                memory_percent REAL,
                network_latency REAL,
                connection_count INTEGER,
                bandwidth_usage REAL,
                packet_loss REAL,
                tcp_retrans REAL,
                anomaly_score REAL
            )
        ''')
        conn.commit()
        return conn
        
    def collect_metrics(self):
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'network_latency': self.measure_latency(),
            'connection_count': len([conn for conn in psutil.net_connections() 
                                   if conn.laddr.port == 22]),
            'bandwidth_usage': self.measure_bandwidth(),
            'packet_loss': self.measure_packet_loss(),
            'tcp_retrans': self.get_tcp_retransmissions()
        }
        return metrics
        
    def measure_latency(self):
        try:
            result = subprocess.run(
                ['ping', '-c', '3', '-q', '8.8.8.8'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                avg_latency = float(result.stdout.split('/')[4])
                return avg_latency
            return -1
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError):
            return -1
            
    def measure_bandwidth(self):
        try:
            net_io = psutil.net_io_counters()
            time.sleep(1)
            net_io_after = psutil.net_io_counters()
            bytes_sent = net_io_after.bytes_sent - net_io.bytes_sent
            bytes_recv = net_io_after.bytes_recv - net_io.bytes_recv
            return (bytes_sent + bytes_recv) / 1024 / 1024  # MB/s
        except Exception as e:
            self.logger.error(f"Error measuring bandwidth: {e}")
            return -1
            
    def measure_packet_loss(self):
        try:
            result = subprocess.run(
                ['ping', '-c', '10', '-q', '8.8.8.8'],
                capture_output=True,
                text=True,
                timeout=15
            )
            if result.returncode == 0:
                packet_loss = float(result.stdout.split('%')[0].split()[-1])
                return packet_loss
            return -1
        except Exception as e:
            self.logger.error(f"Error measuring packet loss: {e}")
            return -1
            
    def get_tcp_retransmissions(self):
        try:
            result = subprocess.run(
                ['netstat', '-s'],
                capture_output=True,
                text=True
            )
            for line in result.stdout.split('\n'):
                if 'segments retransmitted' in line:
                    return float(line.split()[0])
            return 0
        except Exception as e:
            self.logger.error(f"Error getting TCP retransmissions: {e}")
            return -1
            
    def detect_anomalies(self, data):
        if len(data) < 10:
            return 0
            
        try:
            clf = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100,
                max_samples='auto'
            )
            features = [
                'cpu_percent', 'memory_percent', 'network_latency',
                'bandwidth_usage', 'packet_loss', 'tcp_retrans'
            ]
            X = data[features].fillna(-1).values
            scores = clf.fit_predict(X)
            return -1 if scores[-1] == -1 else 1
        except Exception as e:
            self.logger.error(f"Error in anomaly detection: {e}")
            return 0
            
    def optimize_system(self, metrics):
        try:
            if metrics['cpu_percent'] > 80:
                subprocess.run(['renice', '+10', '-p', str(os.getpid())])
                
            if metrics['memory_percent'] > 90:
                subprocess.run(['sync'])
                with open('/proc/sys/vm/drop_caches', 'w') as f:
                    f.write('3')
                    
            if metrics['packet_loss'] > 5:
                self.logger.warning("High packet loss detected, adjusting TCP parameters")
                subprocess.run(['sysctl', '-w', 'net.ipv4.tcp_retries2=8'])
                
            if metrics['tcp_retrans'] > 100:
                self.logger.warning("High TCP retransmissions, optimizing network")
                subprocess.run(['sysctl', '-w', 'net.ipv4.tcp_slow_start_after_idle=0'])
                
        except Exception as e:
            self.logger.error(f"Error in system optimization: {e}")
            
    def handle_shutdown(self, signum, frame):
        self.logger.info("Received shutdown signal, cleaning up...")
        self.running = False
        
    def cleanup(self):
        try:
            self.conn.close()
            self.logger.info("Successfully cleaned up resources")
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")
            
    def run(self):
        self.logger.info("Starting SSH performance monitoring")
        while self.running:
            try:
                metrics = self.collect_metrics()
                df = pd.read_sql('SELECT * FROM performance_metrics', self.conn)
                
                anomaly_score = self.detect_anomalies(df)
                metrics['anomaly_score'] = anomaly_score
                
                cursor = self.conn.cursor()
                cursor.execute('''
                    INSERT INTO performance_metrics 
                    VALUES (:timestamp, :cpu_percent, :memory_percent,
                            :network_latency, :connection_count,
                            :bandwidth_usage, :packet_loss,
                            :tcp_retrans, :anomaly_score)
                ''', metrics)
                self.conn.commit()
                
                if anomaly_score == -1:
                    self.logger.warning("Anomaly detected, applying optimizations")
                    self.optimize_system(metrics)
                
                time.sleep(60)
                
            except Exception as e:
                self.logger.error(f"Error in main monitoring loop: {e}")
                time.sleep(10)
                
        self.cleanup()

if __name__ == '__main__':
    monitor = SSHMonitor()
    monitor.run()
EOL

    chmod +x "${CONFIG_DIR}/ssh_monitor.py"
}

# Create systemd service for monitoring with enhanced reliability
create_monitor_service() {
    cat > /etc/systemd/system/ssh-monitor.service << 'EOL'
[Unit]
Description=SSH Performance Monitor and Optimizer
After=network.target network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
ExecStart=/opt/ssh-optimizer-env/bin/python3 /etc/ssh-optimizer/ssh_monitor.py
Restart=always
RestartSec=30
User=root
Environment=PYTHONUNBUFFERED=1
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WorkingDirectory=/etc/ssh-optimizer
StandardOutput=append:/var/log/ssh-optimizer.log
StandardError=append:/var/log/ssh-optimizer.log

# Security hardening
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_NICE
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOL

    systemctl daemon-reload
    systemctl enable ssh-monitor
    systemctl start ssh-monitor
    
    # Verify service status
    if ! systemctl is-active --quiet ssh-monitor; then
        log "ERROR" "SSH monitor service failed to start"
        journalctl -u ssh-monitor --no-pager -n 50 >> "$LOG_FILE"
        return 1
    fi
}

# Create advanced connection script with protocol selection and fallback mechanisms
create_connection_script() {
    cat > /usr/local/bin/smart-ssh << 'EOL'
#!/bin/bash

set -euo pipefail

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
CONTROL_PATH="~/.ssh/controlmasters/%r@%h:%p"
TIMEOUT=10
RETRY_COUNT=3
MOSH_TIMEOUT=120

# Logging function
log() {
    echo -e "${2:-$GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}" >&2
}

# Network quality assessment
check_network_quality() {
    local host=$1
    local stats
    stats=$(ping -c 5 -q "$host" 2>/dev/null || echo "FAILED")
    
    if [[ $stats == "FAILED" ]]; then
        echo "poor"
        return
    }
    
    local packet_loss
    packet_loss=$(echo "$stats" | grep -oP '\d+(?=% packet loss)')
    
    local latency
    latency=$(echo "$stats" | grep -oP 'avg/max/mdev = \K[\d.]+' | cut -d/ -f1)
    
    if [[ ${packet_loss:-100} -gt 10 || ${latency:-1000} -gt 200 ]]; then
        echo "poor"
    else
        echo "good"
    fi
}

# Dynamic MTU optimization
optimize_mtu() {
    local host=$1
    local default_mtu
    default_mtu=$(ip link show | awk '/mtu/ {print $5}' | head -n1)
    
    # Try different MTU sizes and measure performance
    local best_mtu=$default_mtu
    local best_latency=1000
    
    for mtu in 1500 1492 1450 1400; do
        ip link set dev $(ip route get "$host" | grep -oP '(?<=dev )\w+') mtu $mtu 2>/dev/null || continue
        local current_latency
        current_latency=$(ping -c 3 -M do -s $((mtu-28)) "$host" 2>/dev/null | awk -F'/' 'END{print $5}')
        
        if [[ -n "$current_latency" && "${current_latency%.*}" -lt "${best_latency%.*}" ]]; then
            best_mtu=$mtu
            best_latency=$current_latency
        fi
    done
    
    # Restore best MTU
    ip link set dev $(ip route get "$host" | grep -oP '(?<=dev )\w+') mtu $best_mtu 2>/dev/null
    return 0
}

# Usage information
usage() {
    cat << 'EOF'
Usage: smart-ssh <host> [options]

Advanced SSH connection optimizer with automatic protocol selection and optimization.

Options:
    -p, --port PORT       Specify custom port
    -i, --identity FILE   Use specific identity file
    -t, --timeout SECS    Connection timeout (default: 10)
    -r, --retries NUM     Number of connection retries (default: 3)
    -f, --force-mosh      Force using mosh if available
    -s, --force-ssh       Force using SSH only
    -h, --help           Show this help message

Examples:
    smart-ssh example.com
    smart-ssh -p 2222 user@example.com
    smart-ssh -i ~/.ssh/custom_key example.com
EOF
    exit 1
}

# Parse command line arguments
FORCE_MOSH=0
FORCE_SSH=0
CUSTOM_PORT=""
IDENTITY_FILE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        -p|--port)
            CUSTOM_PORT="$2"
            shift 2
            ;;
        -i|--identity)
            IDENTITY_FILE="$2"
            shift 2
            ;;
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -r|--retries)
            RETRY_COUNT="$2"
            shift 2
            ;;
        -f|--force-mosh)
            FORCE_MOSH=1
            shift
            ;;
        -s|--force-ssh)
            FORCE_SSH=1
            shift
            ;;
        *)
            HOST="$1"
            shift
            ;;
    esac
done

if [[ -z ${HOST:-} ]]; then
    usage
fi

# Create multiplexing directory
mkdir -p ~/.ssh/controlmasters

# Build SSH options
SSH_OPTS=(
    -o "Compression=yes"
    -o "TCPKeepAlive=yes"
    -o "ServerAliveInterval=30"
    -o "ServerAliveCountMax=3"
    -o "ControlMaster=auto"
    -o "ControlPath=$CONTROL_PATH"
    -o "ControlPersist=10m"
    -o "ConnectTimeout=$TIMEOUT"
)

[[ -n $CUSTOM_PORT ]] && SSH_OPTS+=(-p "$CUSTOM_PORT")
[[ -n $IDENTITY_FILE ]] && SSH_OPTS+=(-i "$IDENTITY_FILE")

# Check network quality
log "Checking network quality..."
NETWORK_QUALITY=$(check_network_quality "$HOST")

# Optimize MTU if needed
if [[ $NETWORK_QUALITY == "poor" ]]; then
    log "Optimizing MTU settings..." "$YELLOW"
    optimize_mtu "$HOST"
fi

# Connection logic
if [[ $FORCE_SSH -eq 1 ]]; then
    log "Forced SSH connection mode" "$YELLOW"
    exec ssh "${SSH_OPTS[@]}" "$HOST" "$@"
elif [[ $NETWORK_QUALITY == "poor" && $FORCE_MOSH -eq 0 && -x $(command -v mosh) ]]; then
    log "Poor network quality detected, using Mosh" "$YELLOW"
    MOSH_OPTS=""
    [[ -n $CUSTOM_PORT ]] && MOSH_OPTS="--ssh='ssh -p $CUSTOM_PORT'"
    [[ -n $IDENTITY_FILE ]] && MOSH_OPTS="$MOSH_OPTS --ssh='ssh -i $IDENTITY_FILE'"
    
    eval mosh $MOSH_OPTS --predict=experimental "$HOST" -- tmux new-session -A -s main
else
    # Standard SSH with fallback
    attempt=0
    while ((attempt < RETRY_COUNT)); do
        if ssh "${SSH_OPTS[@]}" "$HOST" "$@"; then
            exit 0
        fi
        ((attempt++))
        log "Connection attempt $attempt failed, retrying..." "$YELLOW"
        sleep 2
    done
    
    log "All connection attempts failed" "$RED"
    exit 1
fi
EOL

    chmod +x /usr/local/bin/smart-ssh
}

# Performance monitoring tools installation
install_monitoring_tools() {
    log "INFO" "Installing additional performance monitoring tools"
    
    # Create monitoring scripts directory
    mkdir -p "${CONFIG_DIR}/tools"
    
    # Connection monitoring script
    cat > "${CONFIG_DIR}/tools/monitor-connections.sh" << 'EOL'
#!/bin/bash

while true; do
    echo "=== SSH Connections ==="
    ss -tn state established '( dport = :22 or sport = :22 )' | \
        awk 'NR>1 {print $4" <-> "$5}'
    
    echo -e "\n=== Connection Stats ==="
    netstat -s | grep -i "tcp\|retransmitted\|failed"
    
    echo -e "\n=== System Load ==="
    uptime
    
    sleep 5
    clear
done
EOL

chmod +x "${CONFIG_DIR}/tools/monitor-connections.sh"
    
    # Create symlink in /usr/local/bin
    ln -sf "${CONFIG_DIR}/tools/monitor-connections.sh" /usr/local/bin/ssh-monitor-connections
}

# Function to Implement smart-ssh features directly in SSH
implement_smart_ssh_features() {
    log "INFO" "Implementing smart-ssh features directly in system SSH configuration"
    
    # Back up original SSH config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%F)
    
    # Create SSH client config directory if it doesn't exist
    mkdir -p /etc/ssh/ssh_config.d

    # Create global SSH client configuration
    cat > /etc/ssh/ssh_config.d/10-optimized.conf << 'EOL'
# Global SSH Client Optimizations
Host *
    # Connection multiplexing
    ControlMaster auto
    ControlPath ~/.ssh/controlmasters/%r@%h:%p
    ControlPersist 10m

    # Performance optimizations
    Compression yes
    TCPKeepAlive yes
    ServerAliveInterval 30
    ServerAliveCountMax 3
    
    # Connection settings
    ConnectTimeout 10
    ConnectionAttempts 3
    
    # TCP forwarding and tunneling
    ExitOnForwardFailure yes
    
    # Roaming and connection persistence
    TCPRcvBufSize 1048576
    TCPSndBufSize 1048576
    
    # Security with performance
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
    MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
    KexAlgorithms curve25519-sha256@libssh.org,curve25519-sha256,diffie-hellman-group16-sha512
    
    # Reuse connections
    IPQoS throughput
    
    # Enable all compression
    Compression delayed
EOL

    # Create controlmasters directory in default location
    mkdir -p /etc/skel/.ssh/controlmasters
    chmod 700 /etc/skel/.ssh/controlmasters

    # Create controlmasters directory for root
    mkdir -p /root/.ssh/controlmasters
    chmod 700 /root/.ssh/controlmasters

    # Add auto-optimization to sshd_config
    cat >> /etc/ssh/sshd_config << 'EOL'

# Auto-optimization settings
MaxSessions 100
MaxStartups 100:30:200
TCPKeepAlive yes
ClientAliveInterval 30
ClientAliveCountMax 3
Compression delayed
IPQoS throughput

# Advanced TCP settings
UseDNS no
GSSAPIAuthentication no
UsePAM yes
PrintMotd no
X11Forwarding no
PermitTunnel yes
EOL

    # Create directory for connection monitoring
    mkdir -p /var/log/ssh-connections

    # Create connection monitoring script
    cat > /usr/local/bin/ssh-connection-monitor << 'EOL'
#!/bin/bash

LOG_FILE="/var/log/ssh-connections/monitor.log"
STATS_FILE="/var/log/ssh-connections/stats.log"

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

while true; do
    # Log current connections
    echo "=== $(date) ===" >> "$LOG_FILE"
    ss -tn state established '( dport = :22 or sport = :22 )' >> "$LOG_FILE"
    
    # Collect statistics
    CONN_COUNT=$(ss -tn state established '( dport = :22 or sport = :22 )' | wc -l)
    LOAD=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}')
    MEM=$(free | awk '/Mem:/ {printf "%.2f", $3/$2 * 100}')
    
    # Log statistics
    echo "$(date +%s),$CONN_COUNT,$LOAD,$MEM" >> "$STATS_FILE"
    
    # Optimize based on current usage
    if [ "$CONN_COUNT" -gt 50 ] || [ "${LOAD%.*}" -gt 5 ]; then
        # Apply aggressive optimizations
        sysctl -w net.ipv4.tcp_fin_timeout=15
        sysctl -w net.ipv4.tcp_keepalive_time=300
    else
        # Reset to normal values
        sysctl -w net.ipv4.tcp_fin_timeout=60
        sysctl -w net.ipv4.tcp_keepalive_time=7200
    fi
    
    sleep 60
done
EOL

    chmod +x /usr/local/bin/ssh-connection-monitor

    # Create systemd service for connection monitoring
    cat > /etc/systemd/system/ssh-connection-monitor.service << 'EOL'
[Unit]
Description=SSH Connection Monitor and Auto-Optimizer
After=network.target sshd.service

[Service]
Type=simple
ExecStart=/usr/local/bin/ssh-connection-monitor
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOL

    # Enable and start the monitoring service
    systemctl daemon-reload
    systemctl enable ssh-connection-monitor
    systemctl start ssh-connection-monitor

    # Create SSH optimization cron job
    cat > /etc/cron.d/ssh-optimizer << 'EOL'
# Run SSH optimization every hour
0 * * * * root /usr/sbin/sysctl -p /etc/sysctl.d/99-ssh-optimizer.conf >/dev/null 2>&1
EOL

    # Update PAM limits for SSH sessions
    cat > /etc/security/limits.d/ssh.conf << 'EOL'
# Increase limits for SSH sessions
*               soft    nofile          65535
*               hard    nofile          65535
*               soft    nproc           65535
*               hard    nproc           65535
EOL

    # Restart SSH service to apply changes
    systemctl restart sshd

    log "INFO" "Smart SSH features have been integrated into system SSH configuration"
    echo "SSH optimization is now active for all SSH connections"
    echo "Monitor connection statistics in /var/log/ssh-connections/"
}

# Main installation function with comprehensive system checks
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

    # Update package lists and upgrade system
    apt-get update || {
        log "ERROR" "Failed to update package lists"
        exit 1
    }
    
    apt-get upgrade -y || {
        log "WARN" "System upgrade failed, continuing with installation"
    }

    # Install required packages with version-specific handling
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
        install_package "$package" || {
            log "ERROR" "Failed to install $package"
            exit 1
        }
    done

    # Setup components with error handling
    setup_python_env || {
        log "ERROR" "Failed to setup Python environment"
        exit 1
    }
    
    optimize_network || {
        log "ERROR" "Network optimization failed"
        exit 1
    }
    
    configure_dns || {
        log "WARN" "DNS configuration failed, continuing with defaults"
    }
    
    configure_ssh || {
        log "ERROR" "SSH configuration failed"
        exit 1
    }
    
    create_monitor_script || {
        log "ERROR" "Failed to create monitoring script"
        exit 1
    }
    
    create_monitor_service || {
        log "ERROR" "Failed to create monitoring service"
        exit 1
    }
    
    create_connection_script || {
        log "ERROR" "Failed to create connection script"
        exit 1
    }
    
    install_monitoring_tools || {
        log "WARN" "Failed to install some monitoring tools"
    }
	
# Implement_smart_ssh_features
        implement_smart_ssh_features || {
        log "WARN" "Failed to implement some smart-ssh features, continuing with basic optimization"
    }

# Restart SSH service
    systemctl restart ssh || {
        log "ERROR" "Failed to restart SSH service"
        exit 1
    }

    # Final verification
    if ! systemctl is-active --quiet ssh; then
        log "ERROR" "SSH service is not running after configuration"
        exit 1
    fi

    # Success message and usage instructions
    log "INFO" "Installation complete! System optimization is active."
    echo -e "${GREEN}Advanced SSH optimization complete!${NC}"
    echo -e "${YELLOW}Usage: smart-ssh hostname [options]${NC}"
    echo -e "${BLUE}Monitor logs: tail -f ${LOG_FILE}${NC}"
    echo -e "${BLUE}Monitor connections: ssh-monitor-connections${NC}"
    echo -e "\nFor best results:"
    echo "1. Allow the monitoring system to collect data for at least 24 hours"
    echo "2. Use smart-ssh instead of regular ssh command"
    echo "3. Check logs regularly for optimization insights"
    echo "4. Run 'ss -tn state established \"( dport = :22 or sport = :22 )\"' to verify connections"
}
main "$@"
