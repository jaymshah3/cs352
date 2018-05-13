CS 352 Wireshark Lab 1 

Write a program which uses the Python dpkt library to read files of saved network packets, and outputs a report of the number of different packet types in the trace file.
Your program (wireshark1.py) accepts a single file name as input with the -f flag. The input file will be in the pcap format, which is generated with the tcpdump, wireshark or tshark commands.  The report is an example of simple packet analysis, for example, detecting possible port-scanners and attacks on a set of local IP addresses. 

Given a pcap file as input, your program will output packet counts as a csv (comma separated values) file. The output report will consist of 4 sections, where each section will be prefaced by a header string. Several pcap files are provided as attachments in the assignment. The contents of each section will be: 

	1. The number of all packets, which includes all types. 

	2. A list of distinct source IP addresses and number of packets for each IP address, including all types of IP packets, such as TCP, UDP ICMP, etc, sorted in descending order of the number of packets from a given source IP address. The IP address should be printed in dotted-decimal notation, and the count as a decimal integer. 

	3. A list distinct destination TCP ports and number of packers for each port, also sorted in descending order of the number of packets from a given destination TCP port.  The port and count should be printed as decimal integers. 

	4. A list of unique source IP/Destination TCP port pairs. The list The number of distinct source IP, destination TCP port pairs, in decreasing count of each pair. The source IP, in dotted decimal, and destination port, as an integer, must be separated by a ":". E.g., 192.168.2.22:80.  

The header strings for each section are:
	1. "Total number of packets,<COUNT>", where <count> is an integer.
	2. "Source IP addresses,count"
	3. "Destination TCP ports,count"
	4. "Source IPs/Destination TCP ports,count"
 
How to get started: 
	One strategy to generate the report is to write a main loop that reads in all the packets on at a time, extracts the needed information from them, and then uses a Python dictionary to store the counts per IP address, TCP port, and IP/Port pairs. The IP addresses and port numbers would be keys, and the value part of the dictionary stores the packet count. After reading the file and building each dictionary, the program would output the keys reverse sorted by value. One method of printing a Python dictionary sorted by value is here. 

In order to read the pcap file and count the packets, look at the tutorial #2 on the dpkt library 

File Attachments: 
	1. A skeleton wireshark1.py file.
	2. 3 test pcap files 
	3. 3 example outputs on the pcap files. Your program should match the counts in these files. 

You must hand in a single file called wireshark1.py 











