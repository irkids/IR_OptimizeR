#!/bin/bash

# Ultra-Advanced SSH Connection Optimizer for Ubuntu (Dynamic Version)
# Features advanced network optimization, performance tuning, and intelligent routing

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

# Enhanced error handling with detailed messages
error_handler() {
    local line_no=$1
    local error_code=$2
    log "ERROR" "Error occurred in script at line: ${line_no}, error code: ${error_code}"
    log "ERROR" "Command that failed: $(sed -n ${line_no}p "$0")"
}
trap 'error_handler ${LINENO} $?' ERR

# Get Ubuntu version and set appropriate package versions
get_ubuntu_version() {
    if ! command -v lsb_release >/dev/null 2>&1; then
        apt-get update && apt-get install -y lsb-release
    fi
    echo "$(lsb_release -rs)"
}

# Check system compatibility and set version-specific configurations
check_system() {
    local version
    version=$(get_ubuntu_version)
    
    # Convert version to float for comparison
    if ! awk -v ver="$version" 'BEGIN{exit!(ver>=18.04)}'; then
        log "ERROR" "This script requires Ubuntu 18.04 or newer"
        exit 1
    fi
    
    # Set Python packages based on Ubuntu version
    if awk -v ver="$version" 'BEGIN{exit!(ver>=22.04)}'; then
        PYTHON_PACKAGES=(
            "python3"
            "python3-pip"
            "python3-venv"
            "python3-dev"
        )
        ML_PACKAGES=(
            "tensorflow"
            "scikit-learn"
        )
    else
        PYTHON_PACKAGES=(
            "python3"
            "python3-pip"
            "python3-venv"
            "python3-dev"
        )
        ML_PACKAGES=(
            "tensorflow-cpu"
            "scikit-learn<1.3"
        )
    fi
}

# Advanced package installation with fallback options and version checking
install_package() {
    local package=$1
    local retries=3
    local delay=5
    local version
    version=$(get_ubuntu_version)

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

    # Version-specific fallback handling
    if awk -v ver="$version" 'BEGIN{exit!(ver>=20.04)}'; then
        # Try universe repository for newer Ubuntu versions
        add-apt-repository universe -y
        apt-get update
    fi

    if ! apt-get install -y --fix-missing "$package"; then
        log "ERROR" "Failed to install $package after all attempts"
        return 1
    fi
}

# Advanced Python environment setup with version-specific packages
setup_python_env() {
    log "INFO" "Setting up Python virtual environment with advanced packages"
    
    python3 -m venv "$VENV_PATH"
    # shellcheck disable=SC1090
    source "${VENV_PATH}/bin/activate"
    
    # Upgrade pip first
    pip install --upgrade pip

    # Install core requirements
    pip install --no-cache-dir \
        paramiko \
        sshtunnel \
        psutil \
        numpy \
        pandas

    # Install ML packages based on Ubuntu version
    local version
    version=$(get_ubuntu_version)
    
    if awk -v ver="$version" 'BEGIN{exit!(ver>=20.04)}'; then
        pip install --no-cache-dir "scikit-learn<1.3"
        pip install --no-cache-dir "tensorflow-cpu<2.11"
    else
        pip install --no-cache-dir scikit-learn
        pip install --no-cache-dir tensorflow
    fi

    # Install remaining packages
    pip install --no-cache-dir \
        pyroute2 \
        netaddr \
        pytest \
        python-daemon
}

# Network optimization using advanced metrics and version-specific parameters
optimize_network() {
    log "INFO" "Applying advanced network optimizations"
    
    local version
    version=$(get_ubuntu_version)
    
    # Configure TCP parameters based on Ubuntu version
    if awk -v ver="$version" 'BEGIN{exit!(ver>=22.04)}'; then
        local congestion_control="bbr2"
    else
        local congestion_control="bbr"
    fi

    # Create sysctl configuration
    cat > /etc/sysctl.d/99-ssh-optimizer.conf << EOL
# Advanced TCP optimizations
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_congestion_control = ${congestion_control}
net.core.default_qdisc = fq_pie
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_low_latency = 1
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

    # Apply sysctl settings
    sysctl --system
    
    # Additional network optimizations
    if command -v ethtool >/dev/null 2>&1; then
        for interface in $(ls /sys/class/net/ | grep -v lo); do
            ethtool -K "$interface" tso on gso on gro on 2>/dev/null || true
        done
    fi
}

[Previous code sections for configure_ssh(), create_monitor_script(), create_monitor_service(), and create_connection_script() remain unchanged]

# Main installation function with enhanced error handling and progress tracking
main() {
    # Check root privileges
    if [ "$EUID" -ne 0 ]; then 
        log "ERROR" "Please run as root"
        exit 1
    }

    # Create necessary directories
    mkdir -p "$CONFIG_DIR"
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"

    # System checks and preparation
    check_system
    log "INFO" "Starting advanced SSH optimization installation"

    # Update package lists and upgrade system
    apt-get update
    apt-get upgrade -y

    # Install required packages
    PACKAGES=(
        "${PYTHON_PACKAGES[@]}"
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

    # Verify installation
    verify_installation

    log "INFO" "Installation complete! System optimization is active."
    echo -e "${GREEN}Advanced SSH optimization complete!${NC}"
    echo -e "${YELLOW}Usage: smart-ssh hostname [options]${NC}"
    echo -e "${BLUE}Monitor logs: tail -f ${LOG_FILE}${NC}"
}

# New function to verify installation and show current performance metrics
verify_installation() {
    log "INFO" "Verifying installation and collecting baseline metrics..."

    # Check SSH service status
    if ! systemctl is-active --quiet ssh; then
        log "WARN" "SSH service is not running properly"
    fi

    # Check Python environment
    if [ ! -d "$VENV_PATH" ]; then
        log "WARN" "Python virtual environment not found"
    fi

    # Display current network settings
    echo -e "${BLUE}Current Network Settings:${NC}"
    sysctl net.ipv4.tcp_congestion_control
    sysctl net.core.default_qdisc

    # Show connection statistics
    if command -v ss >/dev/null 2>&1; then
        echo -e "${BLUE}Current SSH Connections:${NC}"
        ss -tn state established '( dport = :22 or sport = :22 )'
    fi
}

main "$@"
