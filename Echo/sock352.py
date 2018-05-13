
# This is the skeleton code of a cs 352 socket
# You must change the code in the pass statements to make the client and server work. 

import socket as ip

class socket:
    
    def __init__(self):
        self.sock = ip.socket(
            ip.AF_INET, ip.SOCK_STREAM)
        self.con = None
        self.connected = False
    
    def socket():
        return socket()
    
    def bind(self,address):
        self.sock.bind(address)
        self.sock.listen(1)
        self.con, addr = self.sock.accept()
        self.connected = True
    
    def sendto(self,buffer,address):
        if not self.connected:
            self.sock.connect(address)
            self.connected = True

        if self.con is not None:
            sent = self.con.sendall(buffer)
        else:
            sent = self.sock.sendall(buffer)

    def recvfrom(self,nbytes):
        if self.con is not None:
            return self.con.recvfrom(nbytes)
        else:
            return self.sock.recvfrom(nbytes)

    def close(self):
        self.sock.close()

