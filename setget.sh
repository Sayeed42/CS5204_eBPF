#!/bin/bash
n=$1
printf "set foo 0 3600 3\r\nbar\r\n" | nc 192.168.111.2 11211 &
sudo pkill nc
for i in $(eval echo {1..$n})
do
printf "\x00\x00\x00\x00\x00\x01\x00\x00get foo\r\n" | nc -u 192.168.111.2 11211 &
sudo pkill nc
done
