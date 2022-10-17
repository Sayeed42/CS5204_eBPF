#!/bin/bash
echo 1 > /proc/sys/kernel/bpf_stats_enabled
./bmc 3 &
cat /sys/kernel/debug/tracing/trace_pipe &
