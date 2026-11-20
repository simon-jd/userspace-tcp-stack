#!/usr/bin/env bash
set -euo pipefail

echo '== cgroup cpu.stat'
cat /sys/fs/cgroup/cpu.stat
echo '== affinity'
cat /sys/fs/cgroup/cpuset.cpus.effective
echo '== interfaces, queues and counters'
ip -details -statistics link show
ip -4 addr show
ip -4 route show table all
ip neigh show
tc -s qdisc show
echo '== offloads'
ethtool -k eth0
if [[ -e /sys/class/net/utcp0/tun_flags ]]; then
    cat /sys/class/net/utcp0/tun_flags
    ethtool -k utcp0
    ip tuntap show dev utcp0
fi
echo '== network limits and control'
sysctl net.ipv4.tcp_no_metrics_save net.ipv4.tcp_congestion_control \
    net.ipv4.tcp_available_congestion_control net.ipv4.ip_forward \
    net.ipv4.tcp_wmem net.ipv4.tcp_rmem net.core.wmem_max net.core.rmem_max \
    net.ipv4.tcp_sack net.ipv4.tcp_timestamps net.ipv4.tcp_window_scaling
cat /proc/net/snmp /proc/net/netstat
