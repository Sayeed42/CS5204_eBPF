#!/bin/bash
echo 1 > /proc/sys/kernel/bpf_stats_enabled
./xdp_dns 3 &
cat /sys/kernel/debug/tracing/trace_pipe &
sleep 5
./xdp_dns_update add a foo.bar 1.2.3.4 120
./xdp_dns_update add aaaa foo.bar 1:2:3::4 120
