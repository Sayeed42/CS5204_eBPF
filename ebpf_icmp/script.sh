#!/bin/bash
echo 1 > /proc/sys/kernel/bpf_stats_enabled
memcached -l 192.168.111.2 -U 11211 -u memcache &
mount -t bpf none /sys/fs/bpf/
./bmc 3 &
sleep 5
tc qdisc add dev eth0 clsact
tc filter add dev eth0 egress bpf object-pinned /sys/fs/bpf/bmc_tx_filter
cat /sys/kernel/debug/tracing/trace_pipe &
