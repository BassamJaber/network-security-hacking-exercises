#!/usr/bin/env python3
import socket
from binascii import hexlify, unhexlify

HOST = 'netsec.net.in.tum.de'
PORT = 20001
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((HOST, PORT))
sf = s.makefile("rw")  # we use a file abstraction for the sockets


data = sf.readline().rstrip('\n')
print("From Server: `{}'".format(data))

data = sf.readline().rstrip('\n')
print("From Server: `{}'".format(data))

data = input("Your Answer: ")
sf.write("{}\n".format(data))
sf.flush()

data = sf.readline().rstrip('\n')
print("From Server: `{}'".format(data))

data = input("Your Answer: ")
sf.write("{}\n".format(data))
sf.flush()


data = sf.readline().rstrip('\n')
print("From Server: `{}'".format(data))

data = sf.readline().rstrip('\n')
print("From Server: received {} bytes".format(len(data)))

data = unhexlify(data)

pdf_hdr = b'%PDF-1.5'

if len(data) >= len(pdf_hdr) and data[:len(pdf_hdr)] == pdf_hdr:
    print("Looks like we got a PDF!")
    # ADD CODE HERE
    f = open("output.pdf","wb")
    f.write(data)
    f.close()
sf.close()
s.close()


s.close()
