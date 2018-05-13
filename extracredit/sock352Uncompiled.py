#Embedded file name: sock352.py
import socket as ip
import random
import binascii
import threading
import time
import sys
import struct as st
import os
import signal
from inspect import currentframe, getframeinfo
import nacl.utils
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, Box
MESSAGE_TYPE = 69
HEADER_FMT = '!bbLLH'
SYN = 1
ACK = 2
DATA = 4
FIN = 8
MAX_SIZE = 63 * 1024
EXTRA_ENC_DATA = 64
MAX_PKT = 16 + 16 + 16 + MAX_SIZE + EXTRA_ENC_DATA
STATE_INIT = 1
STATE_SYNSENT = 2
STATE_LISTEN = 3
STATE_SYNRECV = 4
STATE_ESTABLISHED = 5
STATE_CLOSING = 6
STATE_CLOSED = 7
STATE_REMOTE_CLOSED = 8
sock352_all_sockets = []
sock352_dbg_level = 10
if os.environ.get('SK_RT') != None:
    SOCK352_DROP_RATE = os.environ.get('SK_RT')

def dbg_print(level, string):
    global sock352_dbg_level
    if sock352_dbg_level >= level:
        print string


class sock352Thread(threading.Thread):

    def __init__(self, threadID, name, delay):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.delay = float(delay)

    def run(self):
        dbg_print(3, 'sock352: timeout thread starting %s delay %.3f ' % (self.name, self.delay))
        scan_for_timeouts(self.delay)
        dbg_print(3, 'sock352: timeout thread %s Exiting ' % self.name)


def scan_for_timeouts(delay):
    global sock352_all_sockets
    time.sleep(delay)
    keep_going = len(sock352_all_sockets) > 0
    while keep_going:
        time.sleep(delay)
        dbg_print(1, 'sock352: scanning for timeouts')
        for sock in sock352_all_sockets:
            skbs = sock.transmit_skbuffs
            dbg_print(3, 'sock352: packet timeout %d buffers' % len(sock.transmit_skbuffs))
            for skbuf in skbs:
                current_time = time.time()
                time_diff = float(current_time) - float(skbuf.time_sent)
                dbg_print(5, 'sock352: packet timeout diff %.3f %f %f ' % (time_diff, current_time, skbuf.time_sent))
                if time_diff > delay:
                    dbg_print(3, 'sock352: packet timeout, retransmitting')
                    sock.transmit(skbuf)

        keep_going = len(sock352_all_sockets) > 0


class Packet():

    def __init__(self):
        self.type = MESSAGE_TYPE
        self.cntl = 0
        self.seq = 0
        self.ack = 0
        self.size = 0
        self.data = ''

    def unpack(self, bytes):
        data_len = len(bytes) - st.calcsize('!bbLLH')
        if data_len >= 0:
            new_format = HEADER_FMT + str(data_len) + 's'
            values = st.unpack(new_format, bytes)
            self.type = values[0]
            self.cntl = values[1]
            self.seq = values[2]
            self.ack = values[3]
            self.size = values[4]
            self.data = values[5]
            dbg_print(1, 'sock352: unpacked:0x%x cntl:0x%x seq:0x%x ack:0x%x size:0x%x data:x%s' % (self.type,
             self.cntl,
             self.seq,
             self.ack,
             self.size,
             binascii.hexlify(self.data)))
        else:
            dbg_print(2, 'sock352 error: bytes to packet unpacker are too short len %d %d ' % (len(bytes), st.calcsize('!bbLLH')))

    def pack(self):
        if self.data == None:
            data_len = 0
        else:
            data_len = len(self.data)
        if data_len == 0:
            bytes = st.pack('!bbLLH', self.type, self.cntl, self.seq, self.ack, self.size)
        else:
            new_format = HEADER_FMT + str(data_len) + 's'
            dbg_print(5, 'cs352 pack: %d %d %d %d %d %s ' % (self.type,
             self.cntl,
             self.seq,
             self.ack,
             self.size,
             self.data))
            bytes = st.pack(new_format, self.type, self.cntl, self.seq, self.ack, self.size, self.data)
        return bytes

    def toHexFields(self):
        if self.data == None:
            retstr = 'type:x%x cntl:x%x seq:x%x ack:x%x sizex:%x' % (self.type,
             self.cntl,
             self.seq,
             self.ack,
             self.size)
        else:
            retstr = 'type:x%x cntl:x%x seq:x%x ack:x%x size:x%x data:x%s' % (self.type,
             self.cntl,
             self.seq,
             self.ack,
             self.size,
             binascii.hexlify(self.data))
        return retstr

    def toHex(self):
        if self.data == None:
            retstr = '%x%x%x%xx%x' % (self.type,
             self.cntl,
             self.seq,
             self.ack,
             self.size)
        else:
            retstr = '%x%x%x%x%xx%s' % (self.type,
             self.cntl,
             self.seq,
             self.ack,
             self.size,
             binascii.hexlify(self.data))
        return retstr


class SKbuff():

    def __init__(self, socket, packet):
        self.sock = socket
        self.time_sent = 0.0
        self.packet = packet


class Socket():

    def __init__(self):
        self.state = STATE_INIT
        self.remote_closed = 0
        self.from_addr = ('', 0)
        self.to_addr = ('', 0)
        self.transmit_skbuffs = []
        self.max_window = 1
        self.receive_skbuffs = []
        self.seq_no = random.randint(0, 65535)
        self.sock = ip.socket(ip.AF_INET, ip.SOCK_DGRAM)
        self.drop_prob = 0.0
        self.random_seed = 0
        self.publicKeysHex = {}
        self.privateKeysHex = {}
        self.publicKeys = {}
        self.privateKeys = {}
        sock352_all_sockets.append(self)

    def set_debug_level(self, level):
        global sock352_dbg_level
        if level >= 0 or level <= 10:
            sock352_dbg_level = level
        else:
            print 'sock352: invalid debug level require [0-10]'
            sock352_dbg_level = 0

    def set_drop_prob(self, probability):
        if probability >= 0.0 or probability <= 1.0:
            self.drop_prob = probability
        else:
            print 'sock352: invalid probability require [0.0-1.0]'
            self.drop_prob = 0.0

    def set_random_seed(self, seed):
        self.random_seed = seed

    def transmit(self, skb):
        address = self.to_addr
        pkt = skb.packet
        bytes = pkt.pack()
        dbg_print(1, 'sock352: transmit: packet: %s ' % pkt.toHexFields())
        dbg_print(2, 'sock352: transmit len %d bytes: %s ' % (len(bytes), binascii.hexlify(bytes)))
        retval = self.sock.sendto(bytes, address)
        skb.time_sent = time.time()
        return retval

    def send_ack(self, pkt, kind):
        address = self.to_addr
        ackPkt = Packet()
        ackPkt.type = MESSAGE_TYPE
        ackPkt.cntl = kind
        ackPkt.seq = 0
        ackPkt.ack = pkt.seq
        ackPkt.size = 0
        ackPkt.data = None
        ackSkb = SKbuff(self, ackPkt)
        self.transmit(ackSkb)

    def cleanup_transmit_queue(self, pkt):
        dbg_print(3, 'sock352: size of transmit queue before ack is %d' % len(self.transmit_skbuffs))
        if pkt.cntl & ACK == ACK:
            for i in range(len(self.transmit_skbuffs)):
                tskb = self.transmit_skbuffs[i]
                dbg_print(7, 'sock352: checking transmit match seq x%x' % tskb.packet.seq)
                if tskb.packet.seq == pkt.ack:
                    dbg_print(7, 'sock352: removing transit buffer packet seq x%x' % pkt.ack)
                    del self.transmit_skbuffs[i]
                    break

        else:
            dbg_print(3, 'sock352: cleanup called on non-ack packet')
        dbg_print(3, 'sock352: size of transmit queue post ack is %d' % len(self.transmit_skbuffs))

    def readKeyChain(self, filename):
        if filename:
            try:
                keyfile_fd = open(filename, 'r')
                for line in keyfile_fd:
                    words = line.split()
                    if len(words) >= 4 and words[0].find('#') == -1:
                        host = words[1]
                        port = words[2]
                        keyInHex = words[3]
                        if words[0].lower() == 'private':
                            self.privateKeysHex[host, port] = keyInHex
                            self.privateKeys[host, port] = nacl.public.PrivateKey(keyInHex, nacl.encoding.HexEncoder)
                        elif words[0].lower() == 'public':
                            self.publicKeysHex[host, port] = keyInHex
                            self.publicKeys[host, port] = nacl.public.PublicKey(keyInHex, nacl.encoding.HexEncoder)

            except Exception as e:
                print 'error: opening keychain file: %s %s' % (filename, repr(e))

        else:
            print 'error: No filename presented'
        return (self.publicKeys, self.privateKeys)

    def bind(self, address):
        if not isinstance(address, tuple):
            print 'sock352: error in bind, address must be of type tuple, not %s ' % type(addr)
            return -1
        self.from_addr = address
        return self.sock.bind(address)

    def connect(self, address):
        dbg_print(3, 'inside connect ')
        if not isinstance(address, tuple):
            print 'sock352: error in connect, address must be of type tuple, not %s ' % type(addr)
            return -1
        self.to_addr = address
        self.transmit_key = None
        for key in self.publicKeys.keys():
            kaddr = key[0]
            kport = key[1]
            if kaddr == address[0]:
                if kport == '*':
                    self.transmit_key = self.publicKeys[key]
                    break
                else:
                    kport = int(kport)
                    if int(kport) == address[1]:
                        self.transmit_key = self.publicKeys[key]
                        break

        if self.transmit_key == None:
            print 'connect: did not find key to %s %d' % (address[0], address[1])
            raise ip.error
        self.nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        self.box = Box(self.privateKeys[('*', '*')], self.transmit_key)
        synPkt = Packet()
        synPkt.type = MESSAGE_TYPE
        synPkt.cntl = SYN
        synPkt.seq = self.seq_no
        synPkt.ack = 0
        synPkt.size = 0
        synPkt.data = ''
        synSkb = SKbuff(self, synPkt)
        self.transmit_skbuffs.append(synSkb)
        self.transmit(synSkb)
        self.state = STATE_SYNSENT
        dbg_print(3, 'connect: synsent ')
        while self.state == STATE_SYNSENT:
            data, addr = self.sock.recvfrom(MAX_SIZE)
            pkt = Packet()
            pkt.unpack(data)
            if pkt.cntl != SYN | ACK:
                dbg_print(1, 'sock352_connect: received packet in connect with SYN ACK not set')
                self.transmit(skb)
                continue
            if pkt.ack == self.seq_no:
                self.cleanup_transmit_queue(pkt)
                self.send_ack(pkt, ACK)
                self.next_recv_no = pkt.seq + 1
                self.state = STATE_ESTABLISHED
                dbg_print(3, 'connect: established')
            else:
                dbg_print(5, 'sock352: connect: got the wrong ack number, expected %x got %x' % (self.seq_no, pkt.ack))
                self.transmit(skb)

    def accept(self):
        self.state = STATE_LISTEN
        self.seq = 39201
        dbg_print(7, 'sock352: inside accept')
        while self.state == STATE_LISTEN:
            data, from_addr = self.sock.recvfrom(MAX_SIZE)
            pkt = Packet()
            pkt.unpack(data)
            if pkt.type != MESSAGE_TYPE:
                dbg_print(1, 'got wrong packet type got 0x%x expected 0x%x' % (pkt.type, MESSAGE_TYPE))
                continue
            if pkt.cntl != SYN:
                dbg_print(1, 'sock352: accept: the packet SYN not set')
                continue
            self.to_addr = from_addr
            self.transmit_key = None
            for key in self.publicKeys.keys():
                kaddr = key[0]
                kport = key[1]
                if kaddr == from_addr[0]:
                    if kport == '*':
                        self.transmit_key = self.publicKeys[key]
                        break
                    else:
                        kport = int(kport)
                        if int(kport) == from_addr[1]:
                            self.transmit_key = self.publicKeys[key]
                            break

            if self.transmit_key == None:
                print 'accept: did not find key to %s %d' % (from_addr[0], from_addr[1])
                raise ip.error
            self.next_recv_no = pkt.seq
            ackPkt = Packet()
            ackPkt.type = MESSAGE_TYPE
            ackPkt.cntl = SYN | ACK
            ackPkt.seq = self.seq_no
            ackPkt.ack = self.next_recv_no = pkt.seq
            ackPkt.data = None
            ackSkb = SKbuff(self, ackPkt)
            self.transmit_skbuffs.append(ackSkb)
            self.transmit(ackSkb)
            self.state = STATE_SYNRECV
            self.next_recv_no = pkt.seq + 1
            self.nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
            self.box = Box(self.privateKeys[('*', '*')], self.transmit_key)
            dbg_print(7, 'sock352: accept: SYNRECV')
            return from_addr

    def sendto(self, buffer):
        pkt = Packet()
        pkt.type = MESSAGE_TYPE
        pkt.cntl = DATA
        self.seq_no = self.seq_no + 1
        pkt.seq = self.seq_no
        if buffer == None:
            pkt.size = 0
            pkt.data = None
        else:
            encrypted = self.box.encrypt(buffer, self.nonce)
            pkt.data = encrypted
            pkt.size = len(encrypted)
        dbg_print(3, pkt.toHexFields())
        skb = SKbuff(self, pkt)
        self.transmit_skbuffs.append(skb)
        return self.transmit(skb)

    def recvfrom(self, nbytes):
        dbg_print(7, 'sock352: inside recvfrom')
        got_data = False
        while got_data == False:
            dbg_print(7, 'sock352: looping in recvfrom')
            if len(self.receive_skbuffs) > 0:
                if self.receive_skbuffs[0].packet.seq + 1 == self.next_recv_no:
                    skb = self.receive_skbuffs.pop(0)
                    pkt = skb.packet
                    addr = skb.from_addr
            else:
                dbg_print(7, 'sock352: recvfrom: waiting for a packet')
                raw_bytes, addr = self.sock.recvfrom(MAX_SIZE)
                dbg_print(7, 'sock352: recvfrom: got packet len %d' % len(raw_bytes))
                pkt = Packet()
                pkt.unpack(raw_bytes)
            if pkt.type != MESSAGE_TYPE:
                dbg_print(3, 'sock352: Wrong packet type')
                got_data = False
                continue
            if self.state == STATE_ESTABLISHED or self.state == STATE_CLOSING or self.state == STATE_SYNRECV:
                dbg_print(7, 'sock352: in state established or syncrecv or closing')
                if pkt.cntl & ACK == ACK:
                    dbg_print(9, 'sock352: ack flag set ')
                    self.cleanup_transmit_queue(pkt)
                    if pkt.cntl == ACK and pkt.size == 0:
                        if self.state == STATE_CLOSING:
                            return None
                        got_data = False
                        continue
                if pkt.cntl & DATA == DATA:
                    dbg_print(3, 'sock352: checking random threshold %.3f' % self.drop_prob)
                    if self.drop_prob > 0.0:
                        r = random.random()
                        dbg_print(3, 'sock352: random drop random draw is %0.3f ' % r)
                        if r <= self.drop_prob:
                            dbg_print(1, 'sock352: dropping received packet')
                            got_data = False
                            continue
                    if pkt.seq == self.next_recv_no:
                        dbg_print(5, 'sock352: recvfrom: data packet seq number matched wanted 0x%x got 0x%x' % (pkt.seq, self.next_recv_no))
                        self.next_recv_no = self.next_recv_no + 1
                        self.send_ack(pkt, ACK)
                        decrypted = self.box.decrypt(pkt.data)
                        if len(decrypted) > nbytes:
                            return decrypted[0:nbytes]
                        else:
                            return decrypted
                    else:
                        dbg_print(5, 'sock352: sequence match failed wanted 0x%x got 0x%x' % (pkt.ack, self.next_recv_no))
                        base = self.seq_no + 1
                        if pkt.seq > base and pkt.seq < base + self.max_window:
                            dbg_print(5, 'sock352: got out-of-order packet in window')
                            found = False
                            for skb in self.receive_skbuffs:
                                if skb.packet.seq == pkt.seq:
                                    found = True
                                    break

                            if found == False:
                                new_skb = SKbuff(self, pkt)
                                self.send_ack(pkt, ACK)
                                self.receive_skbuffs.append(new_skb)
                            else:
                                dbg_print(5, 'sock352: got duplicate on receive list')
                if pkt.cntl & FIN == FIN:
                    dbg_print(3, 'sock352: got FIN packet seq no 0x%x' % pkt.seq)
                    self.remote_closed = STATE_REMOTE_CLOSED
                    self.send_ack(pkt, ACK)
                    if self.state == STATE_CLOSING:
                        got_data = False
                        return None
                    got_data = False
                    continue
                if pkt.cntl & SYN == SYN:
                    dbg_print(1, 'sock352: got SYN packet type in post-syn state')
                    got_data = False
                    continue
                else:
                    dbg_print(1, 'sock352: got unknown packet control bit')
                    got_data = False
                    continue
            else:
                print dbg_print(5, 'socket state error')

    def make_counter(self, int):
        global sock352_make_counter
        sock352_make_counter = sock352_make_counter + '556512922' + str(int)

    def close(self):
        dbg_print(7, 'sock352: inside close')
        self.seq_no = self.seq_no + 1
        pkt = Packet()
        pkt.type = MESSAGE_TYPE
        pkt.cntl = FIN
        self.seq_no = self.seq_no
        pkt.seq = self.seq_no
        pkt.ack = 0
        pkt.size = 0
        pkt.data = None
        skb = SKbuff(self, pkt)
        dbg_print(5, 'sock352: sending FIN to complete close')
        self.transmit_skbuffs.append(skb)
        self.transmit(skb)
        self.state = STATE_CLOSING
        dbg_print(1, 'sock352: socket closed, waiting for transmit queue to drain')
        skb_num = len(self.transmit_skbuffs)
        dbg_print(5, 'sock352: start closing, transmit queue must drain %d buffers' % skb_num)
        count = 0
        while skb_num > 1:
            data = self.recvfrom(MAX_SIZE)
            skb_num = len(self.transmit_skbuffs)
            dbg_print(5, 'sock352: still closing, transmit queue must drain %d buffers' % skb_num)
            time.sleep(0.25)
            count = count + 1

        dbg_print(1, 'sock352: Waiting for remote FIN to complete close')
        while self.remote_closed != STATE_REMOTE_CLOSED:
            data = self.recvfrom(MAX_SIZE)
            time.sleep(0.5)

        self.make_counter(count)


sock352_dbg_level = 0
sock352_make_counter = ''
dbg_print(1, 'starting timeout thread')
thread1 = sock352Thread(1, 'Thread-1', 0.25)
thread1.daemon = True
thread1.start()
