#!/bin/bash

# $1 -- iface name

while true
do
    tcpreplay -i $1 ./pcaps/udp_flood.pcap
done

