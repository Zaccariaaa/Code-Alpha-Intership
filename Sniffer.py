import logging
from datetime import datetime
import subprocess
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

try:
    from scapy.all import *

except ImportError:
    print("Scapy package for Python is not installed on your system.")
    sys.exit()
    

#Asking the user for some parameters: interface on which sniff, the number of packets to sniff, the time interval to sniff, the protocol

#Asking the user for input - the interface on which to run the sniffer
net_iface = input("* Enter the interface on which to run the sniffer : ")

try:
    subprocess.call(["ifconfig", net_iface, "promisc"], stdout = None, stderr = None, shell = False)
 
except:
    print("\nFailed to configure interface as promiscuous.\n")

else:
    #Executed if the try clause does not raise an exception
    print("\nInterface %s was set to PROMISC mode.\n" % net_iface)
    
    
#Asking the user for the number of packets to sniff (the "count" parameter)
pkt_to_sniff = input("* Enter the number of packets to capture : ")

#Consider the case when user enters 0 (infinity)
if int(pkt_to_sniff) != 0:
    print("\nThe program will capture %d packets.\n" % int(pkt_to_sniff))
    
elif int(pkt_to_sniff) == 0:
    print("\nThe program will capture packets until the timeout expires.\n")
    
time_to_sniff = input("* Enter the number of seconds to run the capture: ")

#value entered by the user
if int(time_to_sniff) != 0:
    print("\nThe program will capture packets for %d seconds.\n" % int(time_to_sniff))
    
#Asking the user for any protocol filter he might want to apply to the sniffing process
proto_sniff = input("* Enter the protocol to filter by (arp|bootp|icmp|0 is all): ")

#Considering the case when the user enters 0 (meaning all protocols)
if (proto_sniff == "arp") or (proto_sniff == "bootp") or (proto_sniff == "icmp"):
    print("\nThe program will capture only %s packets.\n" % proto_sniff.upper())
   
elif (proto_sniff) == "0":
    print("\nThe program will capture all protocols.\n")


file_name = input("* Please give a name to the log file: ")


sniffer_log = open(file_name, "a")


#This is the function that will be called for each captured packet
#The function will extract parameters from the packet and then log each packet to the log file
def packet_log(packet):
    
    #Getting the current timestamp
    now = datetime.now()
    
    if proto_sniff == "0":
        #Writing the data to the log file
        print("Time: " + str(now) + " Protocol: ALL" + " SMAC: " + packet[0].src + " DMAC: " + packet[0].dst, file = sniffer_log)
        
    elif (proto_sniff == "arp") or (proto_sniff == "bootp") or (proto_sniff == "icmp"):
        #Writing the data to the log file
        print("Time: " + str(now) + " Protocol: " + proto_sniff.upper() + " SMAC: " + packet[0].src + " DMAC: " + packet[0].dst, file = sniffer_log)

#Printing an informational message to the screen
print("\n* Starting the capture...")

#Running the sniffing process (with or without a filter)
if proto_sniff == "0":
    sniff(iface = net_iface, count = int(pkt_to_sniff), timeout = int(time_to_sniff), prn = packet_log)
    
elif (proto_sniff == "arp") or (proto_sniff == "bootp") or (proto_sniff == "icmp"):
    sniff(iface = net_iface, filter = proto_sniff, count = int(pkt_to_sniff), timeout = int(time_to_sniff), prn = packet_log)
    
else:
    print("\nCould not identify the protocol.\n")
    sys.exit()

#Printing the closing message
print("\n* Please check the %s file to see the captured packets.\n" % file_name)

#Closing the log file
sniffer_log.close()

#End of the program
