#!/bin/bash

PREFIX=/opt/lilitun

SERVER_PORT=80
KEY_FILE=${PREFIX}/etc/key32.dat

IFACE_TUN=lil0
IPADDR_TUN=10.20.0.1/24

ip tuntap add $IFACE_TUN mode tun multi_queue
ip link set $IFACE_TUN up
ip addr add $IPADDR_TUN dev $IFACE_TUN

${PREFIX}/bin/lilitun -i $IFACE_TUN -s -p $SERVER_PORT -k $KEY_FILE -d

ip tuntap del $IFACE_TUN mode tun multi_queue
