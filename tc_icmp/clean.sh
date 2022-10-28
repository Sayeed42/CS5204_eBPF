#!/bin/bash
tc filter del dev eth0 ingress
tc qdisc del dev eth0 clsact
pkill tc_icmp
rm /sys/fs/bpf/icmp_serv
pkill cat
