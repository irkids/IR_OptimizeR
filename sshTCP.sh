#!/bin/bash
tput setaf 7 ; tput settab 4; tput bold; printf '%35s%s%-20s\n' "TCP Tweaker 1.0" ; tput sgr0

# Check if TCP Tweaker settings are already present
if [[ `grep -c "^#PH56" /etc/sysctl.conf` -eq 1 ]]; then
  echo ""
  echo "TCP Tweaker network settings have already been added to the system!"
  
  # Automatically remove the settings
  echo ""
  echo "Removing TCP Tweaker settings..."
  grep -v "^#PH56
net.ipv4.tcp_window_scaling = 1
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 16384 16777216
net.ipv4.tcp_low_latency = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr" /etc/sysctl.conf > /tmp/syscl && mv /tmp/syscl /etc/sysctl.conf
  sysctl -p /etc/sysctl.conf > /dev/null
  
  echo ""
  echo "TCP Tweaker network settings were successfully removed."
  echo ""
  exit
else
  echo ""
  echo "This is an experimental script. Use at your own risk!"
  echo "This script will change some network settings"
  echo "to reduce latency and improve speed."
  
  # Automatically proceed with installation
  echo ""
  echo "Proceeding with installation..."
  
  # Modify network settings
  echo ""
  echo "Modifying the following settings:"
  echo " " >> /etc/sysctl.conf
  echo "#PH56" >> /etc/sysctl.conf
  echo "net.ipv4.tcp_window_scaling = 1
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 16384 16777216
net.ipv4.tcp_low_latency = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
  
  # Apply the settings
  sysctl -p /etc/sysctl.conf
  
  echo ""
  echo "TCP Tweaker network settings have been added successfully."
  echo ""
fi

exit
