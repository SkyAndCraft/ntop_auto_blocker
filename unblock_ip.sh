#!/bin/bash
IP=$1
iptables -D INPUT -s $IP -j DROP
echo "IP $IP débloquée"
