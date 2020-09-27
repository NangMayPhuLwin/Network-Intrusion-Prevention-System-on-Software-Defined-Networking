# run on terminal after Snort's in-line mode is running "python snort_alert.py"
# this script is used to send snort alerts to the remote controller's VM via network sockets (with the used of UNIX sockets)
# you can download the original resources at "https://github.com/John-Lin/pigrelay"

import os
import sys
import time
import socket
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
SOCKFILE = "/tmp/snort_alert"
BUFSIZE = 65863
CONTROLLER_IP = '192.168.1.101'
CONTROLLER_PORT = 51234

class SnortListener():
    def __init__(self):
        self.unsock = None
        self.nwsock = None

    #Open a client on Network Socket
    def start_send(self):
        self.nwsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.nwsock.connect((CONTROLLER_IP, CONTROLLER_PORT))
        except Exception, e:
            logger.info("Network socket connection error: %s" % e)
            sys.exit(1)

    #Open a server on Unix Domain Socket
    def start_recv(self):
        if os.path.exists(SOCKFILE):
            os.unlink(SOCKFILE)
        self.unsock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.unsock.bind(SOCKFILE)
        logger.info("Unix Domain Socket listening...")
        self.recv_loop()

    #Receive Snort alert on Unix Domain Socket and send to Network Socket Server
    def recv_loop(self):
        logger.info("Start the network socket client....")
        self.start_send()
        while True:
            data = self.unsock.recv(BUFSIZE)
            time.sleep(0.5)
            if data:
                logger.debug("Send {0} bytes of data.".format
                             (sys.getsizeof(data)))
                # data == 65900 byte
                self.tcp_send(data) #method to send snort alert to Ryu controller
            else:
                pass

    def tcp_send(self, data):
        self.nwsock.sendall(data)
        logger.info("Send the alert messages to Ryu.")

if __name__ == '__main__':
    server = SnortListener()
    server.start_recv()
