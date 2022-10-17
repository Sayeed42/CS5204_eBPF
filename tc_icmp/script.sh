#!/bin/bash
echo 1 > /proc/sys/kernel/bpf_stats_enabled
mount -t bpf none /sys/fs/bpf/
./bmc &
sleep 5
tc qdisc add dev eth0 clsact
tc filter add dev eth0 ingress bpf object-pinned /sys/fs/bpf/icmp_serv
cat /sys/kernel/debug/tracing/trace_pipe &
