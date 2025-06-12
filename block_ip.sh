#!/bin/bash
IP=$1
iptables -A INPUT -s $IP -j DROP
echo "IP $IP bloquée"
