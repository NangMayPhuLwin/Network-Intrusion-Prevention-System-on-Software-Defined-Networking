#collect flow features "duration, packet-count, byte-count"
# run on terminal "ryu-manager l3-nips.py"

#drop rules on code success
#signature-based intrusion prevention system SNORT is integrated with the centralized Ryu controller to configure drop rules in order to block all the traffic from the previous attacker
#sort alert -->> controller (get source mac) --> drop rule configure on all datapaths
#28-1-2020, error no flow added to the flow-table when "eth_type=ether_types.ETH_TYPE_IP" is not added to OFPMatch()  
#30-1-2020, success, error fix by "match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port, eth_src=src, ipv4_src=srcip, ipv4_dst=dstip)"
#30-1-2020, success, idle_timeout= 10 seconds set for packet-in-handler 
#30-1-2020, fail,flow statstics collection 
#30-1-2020, flow statstics collection, self.monitor_thread = hub.spawn(self.monitor) at every 10 seconds, idle-timeout = 10 seconds 
#25-2-2020, flow-based anomaly detection on every 30 seconds
#26-2-2020, network intrusion prevention system with hybrid of signature-based and anomaly-based detection techniques. 

from __future__ import print_function
import array
import time, timeit
import os
import pandas as pd
from sklearn.preprocessing import minmax_scale # inputs values are needed to normalize between 0 and 1
from sklearn.neural_network import MLPClassifier
import psutil
from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib import snortlib
from ryu.lib import hub
count1 = 0
count2 = 0
p=psutil.Process(os.getpid())
print("The current program is running PID",os.getpid(),p.cpu_percent())
mlp = MLPClassifier(hidden_layer_sizes=(4), activation="logistic", solver='sgd', beta_1=0.5, beta_2=0.5, 
            learning_rate="constant", learning_rate_init=1, momentum=1)

class L3snort(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib}
   
    def __init__(self, *args, **kwargs):
        super(L3snort, self).__init__(*args, **kwargs)
        self.snort = kwargs['snortlib']
        self.snort_port = 3
        self.mac_to_port = {}
    	self.datapaths = {}
        #UNIX DOMAIN SOCKET
        #socket_config = {'unixsock': True}  
        #NETWORK SOCKET CONF    
        socket_config = {'unixsock': False}   
        self.snort.set_config(socket_config)
        self.snort.start_socket_server()

    	file = open("snort_alert.txt", "a+")
    	file.write('\n Alert_msg,Source,Destination')
    	#self.IDS_training()
    	self.monitor_thread = hub.spawn(self.monitor)
        file = open("Predict.txt", "a+")
        file.write('\n dp_id,duration,in_port,eth_src,ipv4_dst,packets,bytes')
        file.close()
    
    # Model training
    def IDS_training(self):
    	# Read cleaned flow statistics data
    	print("Training stage to build a model")
    	X_train = pd.read_csv('/home/ryu-snort/same-net.csv')
    	y_train = X_train["class"]
    	del X_train["class"]
    	X_train.iloc[:]= minmax_scale(X_train.iloc[:])
    	mlp.fit(X_train, y_train.values.ravel())

    def monitor(self):
    	self.logger.info("start flow monitoring")
	global p	
	while p.is_running():
	    file = open("cpu_percent.txt","a+")
	    #monitoring cpu usage
	    cpu = p.cpu_percent()	    
	    print("CPU percent", cpu)
            file.write("\n"+str(cpu))	    	  
	    hub.sleep(1)
	
	    """   	    
            for dp in self.datapaths.values():
            # To collect dp_id, duration, pkt_count, byte_count
        	ofproto = dp.ofproto
        	parser = dp.ofproto_parser
        	req = parser.OFPFlowStatsRequest(dp)
            	dp.send_msg(req)	              
            hub.sleep(10)
	    """
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser    
    	self.datapaths[datapath.id] = datapath
        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        global count1
    	packetin = open("packet_in.txt","a+")        
    	start = timeit.default_timer()
    	msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
          
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})        

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port),
                   parser.OFPActionOutput(self.snort_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:                      
            # check IP Protocol and create a match for IP
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port, eth_src=src, ipv4_src=srcip, ipv4_dst=dstip)                
        	#self.logger.info("packet in %s %s %s %s", dpid, srcip, dstip, in_port)     
        
       		# verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle=10)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions, idle=10)
        	count1 = count1 + 1
        	t = timeit.default_timer() - start 
            	#self.logger.info("packet-in messages : %s take %s seconds",count1,t)
        	packetin.write("\n" + str(count1) + "," + str(t))

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def add_flow(self, datapath, priority, match, actions, idle=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
    
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, idle_timeout=idle, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
    	start = timeit.default_timer()
        global count2
        count2 = count2 + 1           
    	msg = ev.msg        
        #self.logger.info('alertmsg: %s' % ''.join(msg.alertmsg))
        self.signature_based_ips(msg)
        t = timeit.default_timer()-start
    	self.logger.info("Alert: %s take : %s  seconds  to insert drop rules",count2,t)
    
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
    	#file = open("FlowStatsfile.txt", "a+")
        self.logger.info('datapath  duration  in_port  eth_src  ip_dst  out-port  packets  bytes')
        self.logger.info('---------------- -------- ----------------- -------- -------- --------')
        for stat in sorted([flow for flow in body if (flow.priority == 1)], key=lambda flow:
        (flow.match['in_port'], flow.match['eth_src'], flow.match['ipv4_dst'])):
        	self.anomaly_based_ips(ev.msg.datapath.id, stat.match['eth_src'], stat.duration_sec, stat.packet_count, stat.byte_count)

    def signature_based_ips(self, msg):
        pkt = packet.Packet(array.array('B', msg.pkt))        
        eth = pkt.get_protocol(ethernet.ethernet)
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        _icmp = pkt.get_protocol(icmp.icmp)
        src_eth = eth.src

        if _icmp:
            self.logger.info("%r", _icmp)
        if _ipv4:
            self.logger.info("%r", _ipv4)
        if eth:
            self.logger.info("%r", eth)

    	print( "drop rules set in datapaths: block all  traffiic from  source : %s"%src_eth)
    	for datapath in self.datapaths.values():
       		#print( "drop rules set in datapaths")
        	ofproto = datapath.ofproto
        	parser = datapath.ofproto_parser
        	match = parser.OFPMatch(eth_src = src_eth)
        	action  = []              
        	self.add_flow(datapath, 3, match, action, idle=300)
    	file = open("snort_alert.txt", "a+")
    	#print(msg.alertmsg[0]) 
    	file.write("\n" + str(msg.alertmsg[0]) + "," + str(src_eth) + "," +  str(_ipv4.dst))
   
    def anomaly_based_ips(self, datapathid, source_mac, duration, packet, byte):
        print("Flow-based anomaly detection", datapathid, source_mac, duration, packet, byte)
    	dpid = datapathid
    	src = source_mac
    	ids = mlp.predict([[duration, packet, byte]])
    	print("The result is %d"%ids)
    	if ids == 1:
       		self.logger.info('Drop rules set in %016x to drop all packets from the source MAC address %s for 30 seconds', dpid,src)
       		datapath = self.datapaths[dpid]
       		ofproto = datapath.ofproto
       		parser = datapath.ofproto_parser
       		match = parser.OFPMatch(eth_src = src)
       		action = []            
       		self.add_flow(datapath, 2, match, action,30)


    
