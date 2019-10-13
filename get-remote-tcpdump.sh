#!/bin/bash
host=$1
iface=$2

mkfifo /tmp/pcap
ssh $host "sudo sh -c 'tcpdump -i $iface -s0 -U -n -w -'" > /tmp/pcap
