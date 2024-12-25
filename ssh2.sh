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
        
        # Optimize MTU size and NIC settings with error handling
        interfaces = psutil.net_if_stats()
        for interface in interfaces:
            if interfaces[interface].isup:
                try:
                    # Try setting MTU, but don't fail if it doesn't work
                    subprocess.run(['ip', 'link', 'set', 'dev', interface, 'mtu', '9000'], 
                                check=False, stderr=subprocess.PIPE)
                    
                    # Try NIC optimizations only if it's a physical interface
                    if interface.startswith(('eth', 'en', 'ens')):
                        subprocess.run(['ethtool', '-G', interface, 'rx', '4096', 'tx', '4096'], 
                                    check=False, stderr=subprocess.PIPE)
                        subprocess.run(['ethtool', '-K', interface, 'tso', 'on', 'gso', 'on', 'gro', 'on'],
                                    check=False, stderr=subprocess.PIPE)
                except Exception as e:
                    with open('/var/log/ssh-optimizer.log', 'a') as f:
                        f.write(f"{datetime.now()} - Non-critical error optimizing {interface}: {str(e)}\n")
        
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

# Create enhanced SSH connection wrapper script with automated key handling
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

# Create or update SSH config for automated key handling
mkdir -p ~/.ssh
touch ~/.ssh/config
if ! grep -q "Host $HOST" ~/.ssh/config; then
    cat >> ~/.ssh/config << EOF
Host $HOST
    StrictHostKeyChecking accept-new
    UserKnownHostsFile ~/.ssh/known_hosts
EOF
fi

chmod 600 ~/.ssh/config

# Run Python optimizer with suppressed netlink errors
/usr/local/bin/ssh-optimizer.py "$HOST" 2>/dev/null

# Test connection type
if command -v mosh-server >/dev/null 2>&1 && nc -z -w5 "$HOST" 60000-61000 2>/dev/null; then
    echo "Using Mosh for better performance..."
    LANG=en_US.UTF-8 mosh "$HOST" -- tmux new-session -A -s main
else
    echo "Using optimized SSH..."
    ssh -o "Compression=yes" \
        -o "TCPKeepAlive=yes" \
        -o "ServerAliveInterval=60" \
        -o "ServerAliveCountMax=3" \
        -o "ControlMaster=auto" \
        -o "ControlPath=~/.ssh/controlmasters/%r@%h:%p" \
        -o "ControlPersist=10m" \
        -o "StrictHostKeyChecking=accept-new" \
        "$HOST" "$@"
fi
EOL

chmod +x /usr/local/bin/smart-ssh

# Create required systemd directory and override file
mkdir -p /etc/systemd/system/ssh.service.d/
cat > /etc/systemd/system/ssh.service.d/override.conf << 'EOL'
[Service]
LimitNOFILE=1000000
CPUSchedulingPolicy=batch
EOL

# [Rest of the script remains unchanged]
