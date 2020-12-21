#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX. If not, see <http://www.gnu.org/licenses/>.
#
"""
Created on Wed Apr 10 03:08:25 2019

@author: Yousuf

This code uses l2_flow_stat.py (Copyright 2012 William Yu) as a skeleton to 
obtain flow statistics from switches. And the DDoS Detection method is inspired by
SDN-DDoS project (Copyright 2016 Atharva Deshpande)

This is a script for POX controller. It requests flow statistics from switches,
analyze and detect for malicious DDoS traffic. If a DDoS traffic is found,
a flow will be sent to both s1 and s2 to block the malicious IP address and TCP 
source port
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.recoco import Timer

from pox.openflow.of_json import *
import os

#Global Variables
active_ip = {}
blocked_ip = {}
threshold = 50

#Controller sends flow_stats_request to s1 and s2
def _timer_func():
    for connection in core.openflow._connections.values():
        connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

#Output function for users to see what is happening
def _screen_output():
    if active_ip:
        os.system("clear")
        print_blocked_ip()
        print ("Active IPs and packet counts:")
        for ip,packet in active_ip.items():
            print ("IP: %s    TCP Src Port: %s   Packet Counts: %s"%(ip,packet["source_port"],packet["packet_count"]))
        
        #Clear the active_ip dictionary
        active_ip.clear()
    else:
        os.system("clear")
        print_blocked_ip()
        print ("Active IPs and packet counts:")
        for ip,packet in active_ip.items():
            print ("IP: %s    TCP Src Port: %s   Packet Counts: %s"%(ip,packet["source_port"],packet["packet_count"]))
        
#A handler to handle the flow statistics received from s1 and s2 in JSON format
def _handle_flowstats_received (event):
    for flow in event.stats:
        #traffic flow in switch 2
        if (str(flow.match.nw_dst) == "100.100.100.3" or str(flow.match.nw_dst) == "100.100.100.4"):
            if (event.connection.dpid == 2):
                handle_flow(flow)
        #If traffic is not going to H3 or H4            
        elif(str(flow.match.nw_dst) == "100.100.100.1" or str(flow.match.nw_dst) == "100.100.100.2"):
            if (event.connection.dpid == 1):
                handle_flow(flow)
            
#A Helper handler function to handle the flow 
def handle_flow (flow):
    source_ip = str(flow.match.nw_src)
    packet_count = str(flow.packet_count)
    source_port = flow.match.tp_src
    pkt_builder = {}
    
    if (source_ip not in blocked_ip.keys()):
        if (flow.packet_count > threshold):
            ports = []
            ports.append(source_port)
            blocked_ip[source_ip] = ports
            drop_packet_flow(source_ip,source_port)
        else:
            pkt_builder["source_port"] = str(source_port)
            pkt_builder["packet_count"] = packet_count
            active_ip[source_ip]=pkt_builder
    else:
        if (source_port not in blocked_ip[source_ip]):
            if (flow.packet_count > threshold):
                blocked_ip[source_ip].append(source_port)
                drop_packet_flow(source_ip,source_port)
            else:
                pkt_builder["source_port"] = str(source_port)
                pkt_builder["packet_count"] = packet_count
                active_ip[source_ip]=pkt_builder
        else:    
            pkt_builder["source_port"] = str(source_port)
            pkt_builder["packet_count"] = "Dropped All Packets"
            active_ip[source_ip]=pkt_builder
           
#---------------Helper Functions-------------------
#add a flow to both switches to drop all the packets from that ip address with that source port
def drop_packet_flow(src_ip, src_port):
    for connection in core.openflow._connections.values():
        #connection.send(msg)
        msg = of.ofp_flow_mod()
        match = of.ofp_match()
        #L2 protocol
        match.dl_type = 0x0800 #0x800 for IP
        #L3 protocol
        match.nw_proto = 6 #for TCP
        match.nw_src = src_ip
        match.nw_dst = "100.100.100.0/24" #to all hosts
        #L4 protocol
        match.tp_src = src_port
        match.tp_dst = 80
        
       
        msg.match = match
        msg.hard_timeout = 0
        msg.idle_timeout = 0
        connection.send(msg)

#Helper function to print out blocked IP address and TCP source ports
def print_blocked_ip():
    print ("Blocked IPs and TCP ports:")
    for ip,port in blocked_ip.items():
        print ("IP: %s   Blocked Port: %s"%(ip,port))
    #for i in range (len(blocked_ip)):
        #print blocked_ip[i],
    print ("\n")

#--------------Auto run Functions---------------------------------
#attach handlers to listenrs  
#Listens for the swithces' response to the flow_stats_request with the specific handler
core.openflow.addListenerByName("FlowStatsReceived", _handle_flowstats_received)

#Run _timer_func very 0.01 sec and refresh screen_output every 1 sec
Timer(0.01, _timer_func, recurring=True)
Timer(1, _screen_output, recurring=True)
    

    