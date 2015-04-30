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
import time

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
        self.nodes = {}
        self.links = {}
        
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = dapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                     actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                        match=match, instructions=inst)
        datapath.send_msg(mod)
        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self,ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        
        if src not in self.net:
            self.net.add_node(src)
            self.net.add_edge(dpid,src,{'port':in_port})
            self.net.add_edge(src,dpid)
        if dst in self.net:
            path=nx.shortest_path(self.net, src, dst)
            next=path[path.index(dpid)+1]
            out_port=self.net[dpid]['port']
        else:
            out_port = ofproto.OFPP_FLOOD
            
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        
        if out_port != ofproto.OFPP_FLOOD:
                    self.add_flow(datapath, msg.in_port, dst, actions)
        
        out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                    actions=actions)
        datapath.send_msg(out)        

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
         switch_list = get_switch(self.topology_api_app, None)
         switches=[switch.dp.id for switch in switch_list]
         links_list = get_link(self.topology_api_app, None)
         links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
         
         
         #print switches
         #print links
         
         self.net = nx.Graph()
         self.net.add_nodes_from(switches)
         self.net.add_edges_from(links)
         
         print "*******List of switch*******"
         print self.net.nodes()
         
         print "*******List of links********"
         print self.net.edges()
         




