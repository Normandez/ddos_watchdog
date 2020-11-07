#!/bin/bash

# $1 -- iface name

while true
do
    tcpreplay -i $1 ./pcaps/rtp-norm-stream.pcap
done


