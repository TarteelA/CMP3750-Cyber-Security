#Coded by: Tarteel Alkaraan (25847208)
#Last Updated: 24/04/2024
#This is a modified and extended version of (Sarmad, 2024), (Saha, 2024) and (Bhatt, 2024)

#Importing libraries
from socket import *
#Socket module in Python is an interface to Berkeley sockets API
import socket
import random
import re
import scapy.all as scapy
from scapy.all import sniff

  
#Part 1 sniffying traffic
print("\nPart 1 Identifying TCP or UDP Traffic\n")
#Define function to process captured packets
def Handling_Packets(packet):
    print(packet.summary())

#Sniff traffic on default network interface (use 'iface' to specify different interface)
#Also use 'filter' to specify type of packet (tcp, or udp)
#Call packet_handler function for each captured packet
sniff(filter ='tcp',prn=Handling_Packets, count=20)
sniff(filter ='udp',prn=Handling_Packets, count=20)

#Part 2 DNS servers
print("\nPart 2 Identifying DNS Servers\n")
from scapy.all import sniff, DNS, IP
def dns_capture(packet):
    if packet.haslayer(DNS) and packet.haslayer(IP):
        ip_src = packet[IP].src
        dns_query = packet[DNS].qd.qname.decode('utf-8')
        print(f"DNS Query from {ip_src}: {dns_query}")
# Starting our DNS sniffer
sniff(filter="udp port 53", prn=dns_capture, store=0, count= 20)



#Part 3 Identifying network devices (automatic, no need to enter the IP)
def Scan(IP):
    #Create ARP packet
    Request_ARP = scapy.ARP(pdst=IP)
    #Create Ether broadcast packet
    Broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    Broadcast_ARP_Request = Broadcast / Request_ARP
    List_Answered = scapy.srp(Broadcast_ARP_Request, timeout=1, verbose=False)[0]

    #List of outcomes, fill this in upcoming loop
    Outcomes = []

    for element in List_Answered:
        #For each response, append ip and mac address to `outcomes` list
        Outcome = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        Outcomes.append(Outcome)
    
    return Outcomes

def Print_Outcomes(Outcomes):
    #Print outcomes
    print("\nPart 3 Identifying Network Devices")
    print("\nIP Address\t\tMAC Address")
    print("-----------------------------------------")
    for Outcome in Outcomes:
        print(Outcome["ip"] + "\t\t" + Outcome["mac"])

#IP Address for destination
IP_Target = "192.168.0.1/24"
Outcomes_Scan = Scan(IP_Target)
Print_Outcomes(Outcomes_Scan)


#Part 4 Identifying open ports (needs IP, and range of ports)
#Regular Expression Pattern to extract the number of ports
#Specify <lowest_port_number>-<highest_port_number> (ex 10-100)
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
#Initialising the port numbers
port_min = 0
port_max = 65535

PortsTarget = []

#Function to scan network
#Ask user to input target ip to scan
while True:
    print("\nPart 4 Identifying Open Ports")
    HostTarget = "192.168.0.1"
    IPTarget = gethostbyname(HostTarget)
    break

while True:
    #Basic scanner to scan 0-65535 ports
    print("\nPlease Input Range of Ports to scan below e.g.(60-120)")
    port_range = input("Input Port Range: ")
    #Pass port numbers in by removing extra spaces 
    port_range_valid = port_range_pattern.search(port_range.replace(" ",""))
    if port_range_valid:
        #Extracting low end of port scanner range to scan
        port_min = int(port_range_valid.group(1))
        #Extracting upper end of port scanner range to scan
        port_max = int(port_range_valid.group(2))
        break

#Basic socket port scanning
for PortTarget in range(port_min, port_max + 1):
    #Connect to socket of target machine
    try:
        #Create socket object
        #Create socket connection
        # With socket.AF_INET you can enter either a domain name or an ip address 
        # and it will then continue with the connection
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sktnet:
            #Set timeout for socket to connect to server
            #Making duration longer will return better results
            sktnet.settimeout(0.5)
            sktnet.connect((HostTarget, PortTarget))
            PortsTarget.append(PortTarget)
            sktnet.close()
    except:
        pass

#Only open ports
for PortTarget in PortsTarget:
    #Use f string to format string with variables
    print(f"\nPort {PortTarget} Open") 