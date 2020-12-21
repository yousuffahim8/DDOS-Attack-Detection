#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Wed Apr 10 20:48:23 2019

@author: Yousuf
"""
from pox.core import core
from pox.lib.util import dpidToStr
import pox.openflow.libopenflow_01 as of
from pox.lib.recoco import Timer

from pox.openflow.of_json import *
import os

log = core.getLogger()

#Global Variables
active_ip = {}
blocked_ip = []

#Controller sends flow_stats_request to s1 and s2
def _timer_func():
    for connection in core.openflow._connections.values():
        connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
        connection.send(of.ofp_stats_request(body=of.ofp_port_stats_request()))
        
        
#A handler to handle the flow statistics received from s1 and s2 in JSON format
def _handle_flowstats_received (event):
    web_packet = {}
#    stats = flow_stats_to_list(event.stats)
#    for i in stats:
#        print (i)
    for flow in event.stats:
        pkt_info = {}
        if (str(flow.match.nw_dst) == "100.100.100.3" or str(flow.match.nw_dst) == "100.100.100.4"):
            if (event.connection.dpid == 2):
                pkt_info["packet_count"] = flow.packet_count
                pkt_info["src_port"] = flow.match.tp_src
                web_packet[str(flow.match.nw_src)] = pkt_info
#                if web_packet.has_key(str(flow.match.nw_src)):
#                    last_Packet_count= web_packet[str(flow.match.nw_src)]
#                    web_packet[str(flow.match.nw_src)] = last_Packet_count + flow.packet_count
#                else:
#                    web_packet[str(flow.match.nw_src)] = flow.packet_count
                
        #If traffic is not going to H3 or H4            
        elif(str(flow.match.nw_dst) == "100.100.100.1" or str(flow.match.nw_dst) == "100.100.100.2"):
            if (event.connection.dpid == 1):
                pkt_info["packet_count"] = flow.packet_count
                pkt_info["src_port"] = flow.match.tp_src
                web_packet[str(flow.match.nw_src)] = pkt_info
        else:
            print ("didn't go to any of the host")
    
    for ip,pinfo in web_packet.items():
            #if (packet_count != "0"):           
            print ("IP: %s  Source Port: %s  Packet Counts: %s  "%(ip,pinfo["src_port"],pinfo["packet_count"]))
    
    
    #log.debug("FlowStatsReceived from %s: %s", dpidToStr(event.connection.dpid), stats)
    #for flow in event.stats:
    #print (stats)
        
#attach handlers to listenrs  
#Listens for the swithces' response to the flow_stats_request
core.openflow.addListenerByName("FlowStatsReceived", _handle_flowstats_received)

#
Timer(0.1, _timer_func, recurring=True)
#Timer(0.5, _screen_output, recurring=True)

#h1: dl_src = 4a:39:6e:1e:3a:21
#h2: dl_src = 56:56:37:29:10:e9
#h3: dl_src = e2:a9:50:b6:9d:a2
#h4: dl_src = ea:61:0f:0a:5c:e4