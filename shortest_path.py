# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib import hub
import eventlet

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link

import networkx as nx
import matplotlib.pyplot as plt


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app=self
        self.net=nx.DiGraph()
#        hub.spawn(self.show_info)
        

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                     actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                        match=match, instructions=inst)
        datapath.send_msg(mod)
        print "*****************add_flow*****************"
        
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})   
        

        
        
        if src not in self.net.nodes():
            self.net.add_node(src)
            self.net.add_edge(dpid,src,{'port':in_port})
            self.net.add_edge(src,dpid)
            
            print "*****List of nodes*******"
            print self.net.nodes()
            
            print "*****List of edges*******"
            print self.net.edges()

        if dst in self.net.nodes():
            
            try:
                path=nx.shortest_path(self.net, src, dst)
                
                print "*******Path**********"
                print path
                
                next=path[path.index(dpid)+1]
                out_port=self.net[dpid][next]['port']
            except:
                out_port = ofproto.OFPP_FLOOD
        else:
            out_port = ofproto.OFPP_FLOOD
            
        actions = [parser.OFPActionOutput(out_port)]
        
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)
            
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            date = msg.data
        
        out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                    actions=actions, data=data)
        datapath.send_msg(out)    
        
#        print "*********List of nodes**********"
#        print self.net.nodes()
#        print "*********List of links**********"
#        print self.net.edges()             
        



    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
         switch_list = get_switch(self.topology_api_app, None)
         switches=[switch.dp.id for switch in switch_list]
         links_list = get_link(self.topology_api_app, None)
         links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
         
         
         self.net.add_nodes_from(switches)
         self.net.add_edges_from(links)
         
         
#    def get_edges_weight():

#    def show_info(self):
#        while True:
#            nx.draw(self.net)
#            plt.show()
            
#            hub.sleep(10)
         
         

                
            
         