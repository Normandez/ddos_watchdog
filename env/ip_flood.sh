#!/bin/bash

# $1 -- iface name

while true
do
    tcpreplay -i $1 ./pcaps/ip_flood.pcap
done

