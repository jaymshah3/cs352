#!/usr/bin/env python

import dpkt
import datetime
import socket
import argparse

probe_width = 0
probe_min_packets = 0
scan_width = 0
scan_min_packets = 0

# convert IP addresses to printable strings 
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# add your own function/class/method defines here.

def main():
    # parse all the arguments to the client
    parser = argparse.ArgumentParser(description='CS 352 Wireshark Assignment 2')
    parser.add_argument('-f', '--filename', type=str, help='pcap file to input', required=True)
    parser.add_argument('-t', '--targetip', type=str, help='a target IP address', required=True)
    parser.add_argument('-l', '--wp', type=int, help='Wp', required=True)
    parser.add_argument('-m', '--np', type=int, help='Np', required=True)
    parser.add_argument('-n', '--ws', type=int, help='Ws', required=True)
    parser.add_argument('-o', '--ns', type=int, help='Ns', required=True)

    # get the parameters into local variables
    args = vars(parser.parse_args())
    file_name = args['filename']
    target_ip = args['targetip']
    global probe_width 
    probe_width = args['wp']
    global probe_min_packets
    probe_min_packets = args['np']
    global scan_width
    scan_width = args['ws']
    global scan_min_packets
    scan_min_packets = args['ns']

    input_data = dpkt.pcap.Reader(open(file_name,'r'))
    list_udp = []
    list_tcp = []

    for timestamp, packet in input_data:
        # this converts the packet arrival time in unix timestamp format
        # to a printable-string
        time_string = datetime.datetime.utcfromtimestamp(timestamp)
        # your code goes here ...

        eth = dpkt.ethernet.Ethernet(packet)
        ip = eth.data

        eth.time = time_string

        if not isinstance(eth.data, dpkt.ip.IP):
            continue

        ip_dest = inet_to_str(ip.dst)

        #Ignore packets that do not match target dest ip
        if ip_dest != target_ip:
            continue
        
        if ip.p==dpkt.ip.IP_PROTO_TCP:
            list_tcp.append(eth)
        elif ip.p==dpkt.ip.IP_PROTO_UDP:
            list_udp.append(eth)

    print "Reports for TCP"
    
    tcp_port = sort_by_port(list_tcp)
    probe_finder(tcp_port)
    scan_finder(tcp_port)
    # for packet in tcp_port:
        # print "~~DPORT: " + str(packet.data.data.dport)
        # print "~~TIME: " + str(packet.time)

    print "Reports for UDP"
    udp_port = sort_by_port(list_udp)
    probe_finder(udp_port)
    scan_finder(udp_port)

def sort_by_port(packets):
    return sorted(packets, key=lambda packet: (packet.data.data.dport, packet.time))
 
def scan_finder(sorted_time_list):
    prev_packet = None
    scans = []
    curr_scan = []
    for packet in sorted_time_list:
        if prev_packet is None:
            prev_packet = packet
            curr_scan.append(packet)
        else:
            diff_port = (packet.data.data.dport - prev_packet.data.data.dport)
            if diff_port > scan_width:
                if len(curr_scan) >= scan_min_packets:
                    scans.append(curr_scan)

                curr_scan = []
                prev_packet = packet
                curr_scan.append(packet)
            else:
                curr_scan.append(packet)
                prev_packet = packet

    if len(curr_scan) >= scan_min_packets:
        scans.append(curr_scan)

    print "Found {} scans".format(len(scans))
    for scan in scans:
        print "Scan: [{} Packets]".format(len(scan))
        for packet in scan:
            print_packet(packet)

def probe_finder(sorted_port_list):
    prev_packet = None
    probes = []
    curr_probe = []
    for packet in sorted_port_list:
        if prev_packet is None:
            prev_packet = packet
            curr_probe.append(packet)
        else:
            diff_secs = (packet.time - prev_packet.time).total_seconds()
            if (diff_secs > probe_width or
                packet.data.data.dport != prev_packet.data.data.dport):
                if len(curr_probe) >= probe_min_packets:
                    probes.append(curr_probe)

                curr_probe = []
                prev_packet = packet
                curr_probe.append(packet)
            else:
                curr_probe.append(packet)
                prev_packet = packet

    if len(curr_probe) >= probe_min_packets:
        probes.append(curr_probe)

    print "Found {} probes".format(len(probes))
    for probe in probes:
        print "Probes: [{} Packets]".format(len(probe))
        for packet in probe:
            print_packet(packet)

def print_packet(packet):
    print "\t Packet [Timestamp: {}, Port: {}, Source IP: {}]".format(packet.time, packet.data.data.dport, inet_to_str(packet.data.src))  

# execute a main function in Python
if __name__ == "__main__":
    main()







