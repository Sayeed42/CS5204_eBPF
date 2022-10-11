#!/bin/bash
tc filter del dev eth0 egress
tc qdisc del dev eth0 clsact
pkill bmc
pkill memcached
rm /sys/fs/bpf/bmc_tx_filter
pkill cat
