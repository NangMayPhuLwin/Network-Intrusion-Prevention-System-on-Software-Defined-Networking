#this is for online-prediction of traffic on the centralized ryu controller with the used of both Snort signature-NIPS for network traffic and flow-based anomaly detction of flow entries by neural-network
#run on terminal "ryu-manager controller-l4.py"

from ryu.lib import snortlib  # snort library
from __future__ import print_function  # to print snort’s alerts
from ryu.base import app_manager  # to run “ryu-manager”
from ryu.controller import ofp_event  # for OpenFlow events
from ryu.ofproto import ofproto_v1_3  # OF v1.3 definition
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER  # for the state of switches
from ryu.controller.handler import set_ev_cls  # event handler
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib import hub  # to monitor the flow entries
import timeit
import os  # to check details of OS
import pandas as pd  # for data analysis (to read data)
from sklearn.preprocessing import minmax_scale  # for max-min normalization
from sklearn.neural_network import MLPClassifier  # for anomaly-based detection

snort_alert = 0
print("The process ID for current program is", os.getpid())  # to get process ID of controller
mlp = MLPClassifier(hidden_layer_sizes=(7), activation="logistic", solver='sgd', beta_1=0.9, beta_2=0.9,
                    learning_rate="constant", learning_rate_init=0.1, momentum=0.9)


class L4Snort(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib}

    def __init__(self, *args, **kwargs):
        super(L4Snort, self).__init__(*args, **kwargs)  # start the program
        self.snort = kwargs['snortlib']  # start snort  # pass “snortlib” keyword arguments
        self.snort_port = 3  # set the snort_port
        self.mac_to_port = {}  # dictionary #for MAC-port mapping
        self.datapaths = {}  # for switches
        # NETWORK SOCKET CONF
        socket_config = {'unixsock': False}  # snort and ryu are on remote
        self.snort.set_config(socket_config)  # for network socket
        self.snort.start_socket_server()  # start socket sever

    file = open("snort_alert.txt", "a+")
    file.write('\n Alert_msg,Source,Destination')
    self.training()
    self.monitor_thread = hub.spawn(self.monitor)

    # Model training


def training(self):
    # Read cleaned flow statistics data
    print("Training stage to build a model")
    train_time = timeit.default_timer()
    X_train = pd.read_csv('/home/ryu-snort/dataset_6_tuples.csv')
    y_train = X_train["class"]
    del X_train["class"]
    X_train.iloc[:] = minmax_scale(X_train.iloc[:])  # normalize the data
    mlp.fit(X_train, y_train.values.ravel())  # get a trained model
    print("training time:", timeit.default_timer() - train_time)


def monitor(self):
    self.logger.info("start flow monitoring thread")
    while True:
        hub.sleep(30)
        for datapath in self.datapaths.values():
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser
            req = ofp_parser.OFPFlowStatsRequest(datapath)
            datapath.send_msg(req)  # request to send all the flow entries


@set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)  # event handler after snort events receive
def _dump_alert(self, ev):
    snort_start = timeit.default_timer()
    global snort_alert
    snort_alert = snort_alert + 1


msg = ev.msg
# print snort’s alert on controller
self.logger.info('alertmsg: %s' % ''.join(msg.alertmsg))
self.signature_based_ips(msg)  # call sig_based_ips with alert msg
snort = timeit.default_timer() - snort_start
self.logger.info("Alert: %s take : %s  seconds", snort_alert, snort)


# listen for OF events and insert flow entries for table-miss events to receive PACKET_IN messages
@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
def switch_features_handler(self, ev):
    datapath = ev.msg.datapath
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    self.datapaths[datapath.id] = datapath
    match = parser.OFPMatch()
    actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
    self.add_flow(datapath, 0, match, actions)  # listen for table-miss event


# insert flow entries to the switches #PACKET_OUT messages
def add_flow(self, datapath, priority, match, actions, idle=0, buffer_id=None):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
    if buffer_id:
        mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match,
                                idle_timeout=idle, instructions=inst)
    else:
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, idle_timeout=idle, instructions=inst)
    datapath.send_msg(mod)  # PACKET_OUT message


# check for PACKET_IN and extract necessaries for header field of the flow entries
@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
def _packet_in_handler(self, ev):
    msg = ev.msg
    datapath = msg.datapath
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    in_port = msg.match['in_port']
    pkt = packet.Packet(msg.data)
    eth = pkt.get_protocols(ethernet.ethernet)[0]
    if eth.ethertype == ether_types.ETH_TYPE_LLDP:
        # ignore lldp packet
        return
    dst = eth.dst
    src = eth.src
    dpid = datapath.id
    self.mac_to_port.setdefault(dpid, {})  # learn a mac address to avoid FLOOD next time.
    self.mac_to_port[dpid][src] = in_port
    if dst in self.mac_to_port[dpid]:  # if already know dst_mac addresses
        out_port = self.mac_to_port[dpid][dst]
    else:  # else if don’t know the dst address yet.
        out_port = ofproto.OFPP_FLOOD
    actions = [parser.OFPActionOutput(out_port)]
    # install a flow to avoid PACKET_IN next time
    if out_port != ofproto.OFPP_FLOOD:
        # check IP Protocol and create a match for IP
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip = pkt.get_protocol(ipv4.ipv4)
            srcip = ip.src
            dstip = ip.dst
            protocol = ip.proto

            # if ICMP Protocol
            if protocol == in_proto.IPPROTO_ICMP:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port, eth_src=src, ipv4_src=srcip,
                                        eth_dst=dst, ipv4_dst=dstip, ip_proto=protocol)

            #  if TCP Protocol
            elif protocol == in_proto.IPPROTO_TCP:
                t = pkt.get_protocol(tcp.tcp)
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port, eth_src=src, ipv4_src=srcip,
                                        eth_dst=dst, ipv4_dst=dstip, ip_proto=protocol, tcp_src=t.src_port,
                                        tcp_dst=t.dst_port, )

            #  If UDP Protocol
            elif protocol == in_proto.IPPROTO_UDP:
                u = pkt.get_protocol(udp.udp)
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port, eth_src=src, ipv4_src=srcip,
                                        eth_dst=dst, ipv4_dst=dstip, ip_proto=protocol, udp_src=u.src_port,
                                        udp_dst=u.dst_port, )
                # verify if we have a valid buffer_id, if yes avoid to send both FLOW_MOD & PACKET_OUT
            # maximum buffer ID is NO BUFFER to due to OVS bug.
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle=10)
                return
            else:
                self.add_flow(datapath, 1, match, actions, idle=10)
    data = None
    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
        data = msg.data
    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                              in_port=in_port, actions=actions, data=data)
    datapath.send_msg(out)


def signature_based_ips(self, msg):  # snort IPS for packet_based detection
    pkt = packet.Packet(array.array('B', msg.pkt))  # receive snort’s alert msg
    eth = pkt.get_protocol(ethernet.ethernet)  # extract require info
    _ipv4 = pkt.get_protocol(ipv4.ipv4)
    _icmp = pkt.get_protocol(icmp.icmp)
    # src_ip = _ipv4.src
    src_eth = eth.src  # extract source MAC address from that alert
    if _icmp:
        self.logger.info("%r", _icmp)
    if _ipv4:
        self.logger.info("%r", _ipv4)
    if eth:
        self.logger.info("%r", eth)


print("drop rules set in datapaths: block all  traffiic from  source : %s" % src_eth)
for datapath in self.datapaths.values():
    # print( "drop rules set in datapaths")
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    match = parser.OFPMatch(eth_src=src_eth)
    action = []
    self.add_flow(datapath, 3, match, action, block-time)
    #block-time is the blocking time in seconds. You have to set how much time to block
file = open("snort_alert.txt", "a+")
# print(msg.alertmsg[0])
file.write("\n" + str(msg.alertmsg[0]) + "," + str(src_eth) + "," + str(_ipv4.dst))


# collect flow entries for anomaly-based detection of flow entries
@set_ev_cls([ofp_event.EventOFPFlowStatsReply, ], MAIN_DISPATCHER)
def _flow_stats_reply_handler(self, ev):
    body = ev.msg.body
    # print(self.datapaths.values())
    # print (body)


for stat in sorted([flow for flow in body if (flow.priority == 1)]):
    if int(stat.match['ip_proto']) == 1:
        self.anomaly_based_ips(ev.msg.datapath.id, stat.match['eth_src'], stat.duration_sec, stat.match['ip_proto'], 0,
                               0, stat.byte_count, stat.packet_count)
    elif int(stat.match['ip_proto']) == 6:
        self.anomaly_based_ips(ev.msg.datapath.id, stat.match['eth_src'], stat.duration_sec, stat.match['ip_proto'],
                               stat.match['tcp_src'], stat.match['tcp_dst'], stat.byte_count, stat.packet_count)

    elif int(stat.match['ip_proto']) == 17:
        self.anomaly_based_ips(ev.msg.datapath.id, stat.match['eth_src'], stat.duration_sec, stat.match['ip_proto'],
                               stat.match['udp_src'], stat.match['udp_dst'], stat.byte_count, stat.packet_count)



# anomaly-based detection of the flow entries
def anomaly_based_ips(self, datapath_id, source_mac, duration, ip_proto, src_port, dst_port, byte_count, packet_count):
    print("Flow-based anomaly detection of flow entries \n", duration, ip_proto, src_port, dst_port, byte_count,
          packet_count)
    dpid = datapath_id
    src = source_mac
    # predict the flow entries as normal or abnormal
    ids = mlp.predict([[duration, ip_proto, src_port, dst_port, byte_count, packet_count]])
    print("The result is %d" % ids)
    if ids == 1:
        self.logger.info('Drop rules set in %016x to drop all packets from the source MAC address %s ', dpid, src)
        datapath = self.datapaths[dpid]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_src=src)
        action = []
        self.add_flow(datapath, 2, match, action, block-time)
        #block-time is the blocking time in seconds. You have to set how much time to block
