#!/usr/bin/env python3
import socket
from binascii import hexlify, unhexlify



def main():
    # create socket and connect to bob
    HOST = 'netsec.net.in.tum.de'
    PORT = 20005
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Our protocol is line-based. Each message should end with an '\n'. Otherwise, it may result in errors!
    # If your script is stuck (i.e the buffer is not flushed), you probably forgot the newline.

    s.connect((HOST, PORT))
    sf = s.makefile("rw")  # we use a file abstraction for the sockets

    banner = sf.readline().rstrip('\n')
    print("From Bob: `{}'".format(banner)) # you should see the newline at the end printed

    # "SEND ENCRYPTED DATA"
    sf.write("SEND_____ _____DATA\n")
    sf.flush()

    data = sf.readline().rstrip('\n')
    print("From Bob: `{}'".format(data))

    data = sf.readline().rstrip('\n')
    print("From Server: received {} bytes".format(len(data)))

    if ',' in data:
        # IV,ENCRYPTED DATA
        print("Data seems to be encrypted?")
        return

    data = unhexlify(data)

    pdf_hdr = b'%PDF-1.5'

    if len(data) >= len(pdf_hdr) and data[:len(pdf_hdr)] == pdf_hdr:
        print("Looks like we got a PDF!")
        f = open("exercise_5.pdf","wb")
        f.write(data)
        f.close()

    sf.close()
    s.close()


main()

