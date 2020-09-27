#run on host's xterm terminal "python normal_udp.py -s start_ip -e end_ip"
"""
normal traffic to the subnet with the rate of 5 packets per seconds.
send 8 packets per host, total 1000 if i=125
"""
#!/usr/bin/env python
import sys
import getopt
import time
from os import popen
from scapy.all import sendp, IP, UDP, Ether, TCP
from random import randrange

def sourceIPgen():
    # this function generates random IP addresses these values are not valid for first octet of IP address
    not_valid = [10, 127, 254, 255, 1, 2, 169, 172, 192]

    first = randrange(1, 256)

    while first in not_valid:
        first = randrange(1, 256)

    ip = ".".join([str(first), str(randrange(1, 256)), str(randrange(1, 256)), str(randrange(1, 256))])
    return ip
# host IPs start with 10.0.0. the last value entered by user

def gendest(start, end):
    # this function randomly generates IP addresses of the hosts based on
    # #entered start and end values
    first = 10
    second = 0
    third = 0
    ip = ".".join([str(first), str(second), str(third), str(randrange(start, end))])
    return ip
    # send the generated IPs

def main():
    start = 31
    end = 45
    # main method
    try:
        opts, args = getopt.getopt(sys.argv[1:], 's:e:', ['start=', 'end='])
    except getopt.GetoptError:
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-s':
            start = int(arg)
        elif opt == '-e':
            end = int(arg)
    if start == '':
        sys.exit()
    if end == '':
        sys.exit()

    # open interface eth0 to send packets

    interface = popen('ifconfig | awk \'/eth0/ {print $1}\'').read()
    # send normal traffic to the destination hosts

    for i in xrange(125):
        # form the packet
        payload = "send 8 normal UDP packets per one destination"
        packets = Ether()/IP(dst=gendest(start, end), src=sourceIPgen())/UDP(dport=80, sport=2)/payload
        print(repr(packets))
        m = 0
        while m <= 8:
	    #sendp(packets,iface=interface.rstrip(), inter=0.05)            sendp(packets,iface=interface.rstrip(), inter=0.2)
            m +=1

# main
if __name__ == "__main__":
    main()
