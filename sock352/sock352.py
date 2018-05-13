# sock352.py 

# (C) 2018 by R. P. Martin, under the GPL license, version 2.

# this is the skeleton code that defines the methods for the sock352 socket library, 
# which implements a reliable, ordered packet stream using go-back-N.
#
# Note that simultaneous close() is required, does not support half-open connections ---
# that is outstanding data if one side closes a connection and continues to send data,
# or if one side does not close a connection the protocol will fail. 

import socket as ip
import random
import binascii
import threading
import time
import sys
import struct as st
import os
import signal

# The first byte of every packet must have this value 
MESSAGE_TYPE = 0x44

# this defines the sock352 packet format.
# ! = big endian, b = byte, L = long, H = half word
HEADER_FMT = '!bbLLH'

# this are the flags for the packet header 
SYN =  0x01    # synchronize 
ACK =  0x02    # ACK is valid 
DATA = 0x04    # Data is valid 
FIN =  0x08    # FIN = remote side called close 

# max size of the data payload is 63 KB
MAX_SIZE = (63*1024)

# max size of the packet with the headers 
MAX_PKT = ((16+16+16)+(MAX_SIZE))

# these are the socket states 
STATE_INIT = 1
STATE_SYNSENT = 2
STATE_LISTEN  = 3
STATE_SYNRECV = 4 
STATE_ESTABLISHED = 5
STATE_CLOSING =  6
STATE_CLOSED =   7
STATE_REMOTE_CLOSED = 8

socket = None


# function to print. Higher debug levels are more detail
# highly recommended 
def dbg_print(level,string):
    global sock352_dbg_level 
    if (sock352_dbg_level >=  level):
        print string 
    return 

# this is the thread object that re-transmits the packets 
class sock352Thread (threading.Thread):
    
    def __init__(self, threadID, name, delay):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.delay = float(delay)
        
    def run(self):
        dbg_print(3,("sock352: timeout thread starting %s delay %.3f " % (self.name,self.delay)) )
        scan_for_timeouts(self.delay)
        dbg_print(3,("sock352: timeout thread %s Exiting " % (self.name)))
        return 
      
# Example timeout thread function
# every <delay> seconds it wakes up and re-transmits packets that
# have been sent, but not received. A received packet with a matching ack
# is removed from the list of outstanding packets.

def scan_for_timeouts(delay):

    prev_time = time.time()

    # there is a global socket list, although only 1 socket is supported for now 
    while ( True ):
        
        curr_time = time.time()

        if curr_time - prev_time < delay:
            continue

        if socket == None:
            continue

        #thread can close once socket is closed
        if socket.state == STATE_CLOSED:
            return

        for packet in socket.outstanding_packets:
            socket.send_packet(packet) 

        prev_time = time.time()
        
    return 


# This class holds the data of a packet gets sent over the channel 
# 
class Packet:
    def __init__(self, cntl = 0, seq = 0, ack = 0, size = 0, data = '', from_address = ''):
        self.type = MESSAGE_TYPE         # ID of sock352 packet
        self.cntl = cntl                 # control bits/flags 
        self.seq = seq                   # sequence number 
        self.ack = ack                   # acknowledgement number 
        self.size = size                 # size of the data payload 
        self.data = data                 # data 
        self.from_address = from_address # address packet was sent from

    # unpack a binary byte array into the Python fields of the packet 
    def unpack(self,bytes):
        # check that the data length is at least the size of a packet header 
        data_len = (len(bytes) - st.calcsize('!bbLLH'))
        if (data_len >= 0): 
            new_format = HEADER_FMT + str(data_len) + 's'
            values = st.unpack(new_format,bytes)
            self.type = values[0]
            self.cntl = values[1]
            self.seq  = values[2]
            self.ack  = values[3]
            self.size = values[4] 
            self.data = values[5]
            # you dont have to implement the the dbg_print function, but its highly recommended 
            dbg_print (1,("sock352: unpacked:0x%x cntl:0x%x seq:0x%x ack:0x%x size:0x%x data:x%s" % (self.type,self.cntl,self.seq,self.ack,self.size,binascii.hexlify(self.data))))
        else:
            dbg_print (2,("sock352 error: bytes to packet unpacker are too short len %d %d " % (len(bytes), st.calcsize('!bbLLH'))))

        return
    
    # returns a byte array from the Python fields in a packet 
    def pack(self):
        if (self.data == None): 
            data_len = 0
        else:
            data_len = len(self.data)
        if (data_len == 0):
            bytes = st.pack('!bbLLH',self.type,self.cntl,self.seq,self.ack,self.size)
        else:
            new_format = HEADER_FMT + str(data_len) + 's'  # create a new string '!bbLLH30s' 
            dbg_print(5,("cs352 pack: %d %d %d %d %d %s " % (self.type,self.cntl,self.seq,self.ack,self.size,self.data)))
            bytes = st.pack(new_format,self.type,self.cntl,self.seq,self.ack,self.size,self.data)
        return bytes
    
    # this converts the fields in the packet into hexadecimal numbers 
    def toHexFields(self):
        if (self.data == None):
            retstr=  ("type:x%x cntl:x%x seq:x%x ack:x%x sizex:%x" % (self.type,self.cntl,self.seq,self.ack,self.size))
        else:
            retstr= ("type:x%x cntl:x%x seq:x%x ack:x%x size:x%x data:x%s" % (self.type,self.cntl,self.seq,self.ack,self.size,binascii.hexlify(self.data)))
        return retstr

    # this converts the whole packet into a single hexidecimal byte string (one hex digit per byte)
    def toHex(self):
        if (self.data == None):
            retstr=  ("%x%x%x%xx%x" % (self.type,self.cntl,self.seq,self.ack,self.size))
        else:
            retstr= ("%x%x%x%x%xx%s" % (self.type,self.cntl,self.seq,self.ack,self.size,binascii.hexlify(self.data)))
        return retstr


# the main socket class
# you must fill in all the methods
# it must work against the class client and servers
# with various drop rates

class Socket:

    def __init__(self):
        self.socket = ip.socket(ip.AF_INET, ip.SOCK_DGRAM)
        self.state = STATE_INIT
        self.sequence = 0
        self.receive_sequence = 0
        self.send_address = None
        self.outstanding_packets = []
        self.received_fin = False
        global socket
        socket = self
        print socket
        
    # Print a debugging statement line
    # 
    # 0 == no debugging, greater numbers are more detail.
    # You do not need to implement the body of this method,
    # but it must be in the library.
    def set_debug_level(self, level):
        pass 

    # Set the % likelihood to drop a packet
    #
    # you do not need to implement the body of this method,
    # but it must be in the library,
    def set_drop_prob(self, probability):

        pass 

    # Set the seed for the random number generator to get
    # a consistent set of random numbers
    # 
    # You do not need to implement the body of this method,
    # but it must be in the library.
    def set_random_seed(self, seed):
        self.random_seed = seed 
        
    # bind the address to a port
    def bind(self,address):
        return self.socket.bind(address)

    # connect to a remote port
    def connect(self,address):
        self.state = STATE_SYNSENT
        self.send_address = address
        
        packet_connect = Packet(cntl = SYN,
            seq = self.sequence)
        self.append_to_outstanding_packets(packet_connect)
        self.send_packet(packet_connect)

        while True:
            packet_received = self.get_next_packet()
            if (packet_received.cntl == SYN | ACK 
                and packet_received.ack == self.sequence):

                self.state = STATE_ESTABLISHED
                self.delete_from_outstanding_packets(packet_received.ack)
                self.send_acknowledgement(packet_received.seq)
                self.receive_sequence = packet_received.seq + 1
                return

    #accept a connection
    def accept(self):
        self.state = STATE_LISTEN
        
        while True:
            packet = self.get_next_packet()
            if packet.cntl == SYN:
                self.send_address = packet.from_address
                self.state = STATE_SYNRECV
                self.receive_sequence = packet.seq + 1
                #special packet that has both syn and ack flags
                syn_ack_packet = Packet(cntl = SYN | ACK,
                    seq = self.sequence,
                    ack = packet.seq)

                self.append_to_outstanding_packets(syn_ack_packet)
                self.send_packet(syn_ack_packet)

                return packet.from_address

    # send a message up to MAX_DATA
    def sendto(self, buffer):
        self.sequence += 1
        packet = Packet(cntl = DATA,
            seq = self.sequence,
            size = len(buffer),
            data = buffer)

        self.append_to_outstanding_packets(packet)
        return self.send_packet(packet)

    # receive a message up to MAX_DATA
    def recvfrom(self, nbytes):
        while True:
            packet = self.get_next_packet()
            if packet.cntl == DATA:
                if packet.seq == self.receive_sequence:
                    self.receive_sequence += 1
                    self.send_acknowledgement(packet.seq)
                    return packet.data
            elif packet.cntl == ACK:
                self.delete_from_outstanding_packets(packet.ack)
                if self.state == STATE_CLOSING:
                    return
            elif packet.cntl == FIN:
                #MAY NEED TO SEND ACK
                self.received_fin = True
                if self.state == STATE_CLOSING:
                    return

    # close the socket and make sure all outstanding data is delivered 
    # You must implement this method         
    def close(self):
        self.state = STATE_CLOSING
        self.sequence += 1
        packet = Packet(seq = self.sequence,
            cntl = FIN)

        self.send_packet(packet)

        while (len(self.outstanding_packets) != 0 
            or not self.received_fin):
            self.recvfrom(MAX_SIZE)

        self.state = STATE_CLOSED



    def append_to_outstanding_packets(self, packet):
        self.outstanding_packets.append(packet)

    def get_next_packet(self):
        bytes, address = self.socket.recvfrom(MAX_SIZE)
        packet = Packet(from_address = address)
        packet.unpack(bytes)
        return packet

    def send_packet(self, packet):
        data = packet.pack()
        return self.socket.sendto(data, self.send_address)

    def delete_from_outstanding_packets(self, sequence):
        for packet in self.outstanding_packets:
            if packet.seq == sequence:
                self.outstanding_packets.remove(packet)
                return

    def send_acknowledgement(self, sequence):
        packet = Packet(ack = sequence, cntl = ACK)
        self.send_packet(packet)


# Example how to start a start the timeout thread
global sock352_dbg_level 
sock352_dbg_level = 0
dbg_print(3,"starting timeout thread")

# create the thread 
thread1 = sock352Thread(1, "Thread-1", 0.01)

# you must make it a daemon thread so that the thread will
# exit when the main thread does. 
thread1.daemon = True

# run the thread 
thread1.start()

