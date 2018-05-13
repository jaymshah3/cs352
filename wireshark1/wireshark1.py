#!/usr/bin/python
# 
# This is the skeleton of the CS 352 Wireshark Assignment 1
#
# (c) 2018, R. P. Martin, GPL version 2

# Given a pcap file as input, you should report:
#
#1) number of the packets (use number_of_packets), 
#2) list distinct source IP addresses and number of packets for each IP address, in descending order 
#3) list distinct destination TCP ports and number of packets for each port(use list_of_tcp_ports, in descending order)
#4) The number of distinct source IP, destination TCP port pairs, in descending order 

import dpkt
import socket
import argparse 
from collections import OrderedDict

# this helper method will turn an IP address into a string
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# main code 
def main():
    number_of_packets = 0             # you can use these structures if you wish 
    list_of_ips = dict()
    list_of_tcp_ports = dict()
    list_of_ip_tcp_ports = dict()

    # parse all the arguments to the client 
    parser = argparse.ArgumentParser(description='CS 352 Wireshark Assignment 1')
    parser.add_argument('-f','--filename', help='pcap file to input', required=True)

    # get the filename into a local variable
    args = vars(parser.parse_args())
    filename = args['filename']

    # open the pcap file for processing 
    input_data=dpkt.pcap.Reader(open(filename,'r'))

    # this main loop reads the packets one at a time from the pcap file
    for timestamp, packet in input_data:
        eth = dpkt.ethernet.Ethernet(packet)
        
        number_of_packets += 1

        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        
        ip = eth.data
        ip_src = inet_to_str(ip.src) #source IP
        if not ip_src in list_of_ips:
            list_of_ips[ip_src] = 1
        else:
            list_of_ips[ip_src] += 1

        if ip.p == dpkt.ip.IP_PROTO_TCP: #destination TCP
            tcp = ip.data
            dport = str(tcp.dport)
            if not dport in list_of_tcp_ports:
                list_of_tcp_ports[dport] = 1
            else:
                list_of_tcp_ports[dport] += 1

            ip_and_dp = ip_src + ':' + dport #source IP and destination TCP
            if not ip_and_dp in list_of_ip_tcp_ports:
                list_of_ip_tcp_ports[ip_and_dp] = 1
            else:
                list_of_ip_tcp_ports[ip_and_dp] += 1

    print "Total number of packets,%d" % (number_of_packets)
   
    print "Source IP addresses,count"
    for key, value in sorted(list_of_ips.items(), key = lambda x: x[1], reverse = True):
        print key + ',' + str(value)

    print "Destination TCP ports,count"
    for key, value in sorted(list_of_tcp_ports.items(), key = lambda x: x[1], reverse = True):
        print key + ',' + str(value)

    print "Source IPs/Destination TCP ports,count"
    for key, value in sorted(list_of_ip_tcp_ports.items(), key = lambda x: x[1], reverse = True):
        print key + ',' + str(value)

# execute a main function in Python
if __name__ == "__main__":
    main()    



















