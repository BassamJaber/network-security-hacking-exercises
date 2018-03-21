#!/usr/bin/env python3
import socket
from binascii import hexlify, unhexlify
import sys



#username = input("Username (hint: root): ")
#password = input("Password (hint: PasswordXX, X=0-9): ")
#credentials=username+","+password

#port scanned in previous phase
PORT = 49467  #(49151, 50199)
HOST = 'netsec.net.in.tum.de'
security_goals = ('dataintegrity', 'confidentiality', 'availability', 'authenticity', 'accountability', 'controlledaccess')

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect_ex((HOST, PORT))

		
sf = s.makefile("rw")  # we use a file abstraction for the sockets


data = sf.readline().rstrip('\n')
print("From Server: `{}'".format(data))
data = sf.readline().rstrip('\n')
print("From Server: `{}'".format(data))
data = sf.readline().rstrip('\n')
print("From Server: `{}'".format(data))
data = sf.readline().rstrip('\n')
print("From Server: `{}'".format(data))
print("sending security goals to unlock the secrets"+str(security_goals))
response="dataintegrity,confidentiality,availability,authenticity,accountability,controlledaccess"
sf.write("{}\n".format(response))
sf.flush()


data = sf.readline().rstrip('\n')
print("From Server: `{}'".format(data))

data = sf.readline().rstrip('\n')
print("From Server: received {} bytes".format(len(data)))



data = unhexlify(data)
pdf_hdr = b'%PDF-1.5'

if len(data) >= len(pdf_hdr) and data[:len(pdf_hdr)] == pdf_hdr:
    print("Looks like we got a PDF!")
    with open('data_recieved.pdf', mode='wb') as f:
        f.write(data)
        sys.exit(0)


sf.close()
s.close()


s.close()
