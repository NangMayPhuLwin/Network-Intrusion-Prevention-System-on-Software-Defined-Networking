# run on terminal "ryu-manager flow-collect-l4.py"
# collect features from flow-entries of L4: duration, ip-protocol, src-port,dst-port, byte-count, packet-count
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib import hub


class FlowCollect(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FlowCollect, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self.monitor)

    def monitor(self):
        self.logger.info("start flow monitoring thread")
        while True:
            hub.sleep(10)
        print(self.datapaths.values())
        for datapath in self.datapaths.values():
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser
            req = ofp_parser.OFPFlowStatsRequest(datapath)
            datapath.send_msg(req)


@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
def switch_features_handler(self, ev):
    datapath = ev.msg.datapath
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    self.datapaths[datapath.id] = datapath
    match = parser.OFPMatch()
    actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                      ofproto.OFPCML_NO_BUFFER)]
    self.add_flow(datapath, 0, match, actions)


def add_flow(self, datapath, priority, match, actions, idle=0, buffer_id=None):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser

    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                         actions)]
    if buffer_id:
        mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                priority=priority, match=match, idle_timeout=idle,
                                instructions=inst)
    else:
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, idle_timeout=idle, instructions=inst)
    datapath.send_msg(mod)


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
    self.mac_to_port.setdefault(dpid, {})

    # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

    # learn a mac address to avoid FLOOD next time.
    self.mac_to_port[dpid][src] = in_port

    if dst in self.mac_to_port[dpid]:
        out_port = self.mac_to_port[dpid][dst]
    else:
        out_port = ofproto.OFPP_FLOOD

    actions = [parser.OFPActionOutput(out_port)]

    # install a flow to avoid packet_in next time
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

                # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
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


@set_ev_cls([ofp_event.EventOFPFlowStatsReply, ], MAIN_DISPATCHER)
def _flow_stats_reply_handler(self, ev):
    body = ev.msg.body
    file = open("flow_collect.txt", "a+")
    print(body)
    for stat in sorted([flow for flow in body if (flow.priority == 1)], key=lambda flow:
    (flow.match['in_port'], flow.match['eth_src'], flow.match['ipv4_dst'])):
        for stat in sorted([flow for flow in body if (flow.priority == 1)]):
            if int(stat.match['ip_proto']) == 1:
                file.write("\n" + str(ev.msg.datapath.id) + "," + str(stat.match['eth_src']) + "," + str(
                    stat.duration_sec) + "," + str(stat.match['ip_proto']) + "," +  “0” + "," + “0” + "," + str(
                    stat.byte_count) + "," + str(stat.packet_count) + "," + “0” )
                elif int(stat.match['ip_proto']) == 6:
                file.write("\n" + str(ev.msg.datapath.id) + "," + str(stat.match['eth_src']) + "," + str(
                    stat.duration_sec) + "," + str(stat.match['ip_proto']) + "," + str(
                    stat.match['tcp_src']) + "," + str(stat.match['tcp_dst']) + "," + str(stat.byte_count) + "," + str(
                    stat.packet_count) + "," + “0”)
                elif int(stat.match['ip_proto']) == 17:
                file.write("\n" + str(ev.msg.datapath.id) + "," + str(stat.match['eth_src']) + "," + str(
                    stat.duration_sec) + "," + str(stat.match['ip_proto']) + "," + str(
                    stat.match['udp_src']) + "," + str(stat.match['udp_dst']) + "," + str(stat.byte_count) + "," + str(
                    stat.packet_count) + "," + “0”  )
                    # label class 0 for normal & class 1 for attack.
