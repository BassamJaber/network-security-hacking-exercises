#!/usr/bin/env python3
import socket
from Crypto.Cipher import AES
from Crypto.Hash import SHA512, SHA256
from binascii import hexlify, unhexlify



def main():
    # create socket and connect to bob
    HOST = 'netsec.net.in.tum.de'
    PORT = 20006
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Our protocol is line-based. Each message should end with an '\n'. Otherwise, it may result in errors!
    # If your script is stuck (i.e the buffer is not flushed), you probably forgot the newline.

    s.connect((HOST, PORT))
    sf = s.makefile("rw")  # we use a file abstraction for the sockets

    banner = sf.readline()
    print("From Bob: `{}'".format(banner)) # you should see the newline at the end printed

    # "SEND ME THE DATA ENCRYPTED"
    ciphertext=unhexlify(b"798e0ff8b06cc27c1591a4088531a64a9b76a9be87a3e944c6e7000f24f5b9f9")
    hashfunc=SHA256.new()
    hashfunc.update(ciphertext)
    h=hashfunc.digest()
    h2=str(hexlify(h))
    h2=h2.split('\'')[1]

    cmd="8f6f27b5dbfa2ba8367262bda7154d95,798e0ff8b06cc27c1591a4088531a64a9b76a9be87a3e944c6e7000f24f5b9f9,"+h2+"\n"
    sf.write(cmd+","+h2+"\n")
    sf.flush()

    data = sf.readline()
    if len(data) < 1024:
        print("From Bob: `{}'".format(data))
    else:
        print("received {} bytes".format(len(data)))

    data = data.rstrip('\n') # remove trailing newline

    print(data)
    if 'rror' in data:
        print("Error {}".format(data))
        return
    
    if ',' in data:
        data = data.split(",")
        #assert len(data) == 2
        #iv, data = data
        print("Encrypted data, cannot continue")
        return
    
    data = unhexlify(data)
    pdf_hdr = b'%PDF-1.5'
    if len(data) >= len(pdf_hdr) and data[:len(pdf_hdr)] == pdf_hdr:
        print("Looks like we got a PDF!")
        with open('data_recieved.pdf', mode='wb') as f:
            f.write(data)


    sf.close()
    s.close()


main()

