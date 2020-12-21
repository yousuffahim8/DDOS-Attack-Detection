# Final-Project-DDOS-Detection with POX controller
Simulated HTTP DDoS attack in Mininet network. And detect with a POX script. 

How to Run this project:
1. Download this project onto your mininet virtual machine, or the machine that you're running mininet. 
2. Copy traffic_generator.py, detect_ddos.py, generate_packet.py into ~/pox/ext directory
3. Run the topology file projectTopo.mn (i.e. sudo ~/mininet/examples/miniedit.py to run it in miniedit)
4. On another terminal, cd /pox, then run the command:./pox.py forwarding.l3_learning detect_ddos to start up the POX controller
5. In one of the host1-3 terminal, run: sudo python traffic_generator.py  This will start to generate traffic to H4. 
6. Run: sudo python test.py to generate traffic with specific source IP address, tcp source port and number of packets. 

