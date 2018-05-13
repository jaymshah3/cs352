#!/usr/bin/python

# echo server for CS 352 
# (c) 2018, R. P. Martin, under GPL Version 2

# this sever echos back whatever it gets, up to the max of 64K 

import argparse
import time
import struct 
import md5
import os 
import sock352

MAX_SIZE = (1024*63)

def main():
    # parse all the arguments to the client 
    parser = argparse.ArgumentParser(description='CS 352 Socker Echo Server ')
    parser.add_argument('-l','--localport', help='local sock352 UDP port', required=True)

    args = vars(parser.parse_args())
    local_port =  int(args['localport'])
    
    serverSock = sock352.socket()
    serverSock.bind(('', local_port))
# forever waiting for message 
    while True:
        #Read from UDP socket into message, client address 
        message, clientAddress = serverSock.recvfrom(MAX_SIZE)
        serverSock.sendto(message,clientAddress)

# this gives a main function in Python
if __name__ == "__main__":
    main()
