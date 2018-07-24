#!/bin/bash

PREFIX=/opt/lilith

SERVER_ADDR=127.0.0.1
SERVER_PORT=80
KEY_FILE=${PREFIX}/etc/key32.dat

IFACE_TUN=lil0
IPADDR_TUN=10.20.0.2/24

DNS="nameserver 8.8.8.8\n
nameserver 8.8.4.4\n
"

setup_dns() {
    if [ -x /sbin/resolvconf ]; then

	cp -f /var/run/resolvconf/interface/eth0.dhclient /var/run/openvpn/eth0.dhclient.${IFACE_TUN}.backup

	/sbin/resolvconf -d eth0.dhclient

	echo -n -e "$DNS" | /sbin/resolvconf -a "${IFACE_TUN}.lilith"

	/sbin/resolvconf -u

	/sbin/resolvconf --disable-updates

    else

	echo -n -e $DNS > /etc/resolv.conf

    fi
}

restore_dns() {
    if [ -x /sbin/resolvconf ]; then

	/sbin/resolvconf -d "${IFACE_TUN}.lilith"

	cat /var/run/openvpn/eth0.dhclient.${IFACE_TUN}.backup | /sbin/resolvconf -a eth0.dhclient

	rm -f /var/run/openvpn/eth0.dhclient.${IFACE_TUN}.backup

	/sbin/resolvconf -u

	/sbin/resolvconf --enable-updates
    fi
}

ip tuntap add $IFACE_TUN mode tun
ip link set $IFACE_TUN up
ip addr add $IPADDR_TUN dev $IFACE_TUN

setup_dns

${PREFIX}/bin/lilitun -i $IFACE_TUN -c $SERVER_ADDR  -p $SERVER_PORT -k $KEY_FILE -d

restore_dns

ip tuntap del $IFACE_TUN mode tun
