#!/bin/bash
tc filter del dev eth0 ingress
tc qdisc del dev eth0 clsact
pkill bmc
rm /sys/fs/bpf/icmp_serv
pkill cat
