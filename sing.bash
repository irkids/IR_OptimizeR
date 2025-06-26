#!/bin/bash

set -e

echo "📥 Downloading Sing-box version 1.12.0-beta.26..."

# Create the required directory
mkdir -p /etc/s-box/sing-box-1.11.13-linux-amd64v3
cd /tmp

# Download the stable kernel
wget -O sing-box.tar.gz https://github.com/SagerNet/sing-box/releases/download/v1.12.0-beta.26/sing-box-1.12.0-beta.26-linux-amd64.tar.gz

# Extract the archive
tar -xvzf sing-box.tar.gz

# Check if the executable exists
if [ ! -f sing-box-1.12.0-beta.26-linux-amd64/sing-box ]; then
    echo "❌ Sing-box executable not found!"
    exit 1
fi

# Copy to the path expected by the original script
cp sing-box-1.12.0-beta.26-linux-amd64/sing-box /etc/s-box/sing-box-1.11.13-linux-amd64v3/
chmod +x /etc/s-box/sing-box-1.11.13-linux-amd64v3/sing-box

echo "✅ Sing-box installed successfully!"
