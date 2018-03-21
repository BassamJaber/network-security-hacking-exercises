#!/usr/bin/env python3

import sys, os, random
import string
import asyncio
import logging
import concurrent.futures
# library pycrypto
from Crypto.Cipher import AES
import hashlib
from binascii import hexlify, unhexlify


log = logging.getLogger(__name__)
clients = {}  # task -> (reader, writer)

stored_data = None #binary
encryption_key = None


def accept_client(client_reader, client_writer):
    task = asyncio.Task(handle_client(client_reader, client_writer))
    clients[task] = (client_reader, client_writer)

    def client_done(task):
        del clients[task]
        client_writer.close()
        log.info("connection closed")

    task.add_done_callback(client_done)


@asyncio.coroutine
def read_line_safe(client_reader):
    try:
        if client_reader.at_eof():
            return None
        try:
            data = yield from asyncio.wait_for(client_reader.readline(), timeout=30.0)
        except concurrent.futures.TimeoutError:
            return None
        if data is None:
            log.warning("Received no data")
            return None
        if not data.endswith(b"\n"):
            log.warning("read partial data:`%s'" % data)
            return None
        data = data.decode().rstrip()
        if not data:
            log.warning("no data")
            data = ""
        return data
    except Exception as e:
        log.error("EXCEPTION (read_line_safe): %s (%s)" % (e, type(e)))
        return None

@asyncio.coroutine
def handle_client(client_reader, client_writer):
    try:
        remote = client_writer.get_extra_info('peername')
        if remote is None:
            log.error("Could not get ip of client")
            return
        remote = "%s:%s" % (remote[0], remote[1])
        log.info("new connection from: %s" % remote)
    except Exception as e:
        log.error("EXCEPTION (get peername): %s (%s)" % (e, type(e)))
        return

    try:
        client_writer.write("Welcome to Bob's data storage\n".encode())

        cmd = yield from read_line_safe(client_reader)

        if cmd is None:
            client_writer.write("No command received\n".encode())
            return

        def encrypt(plaintext):
            
            # encrypting the plaintext as requested by the command
            iv=os.urandom(AES.block_size)
            #add padding
            if len(plaintext) % 16 != 0:
                plaintext += b'_' * (16 - len(plaintext) % 16)
            cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(plaintext)

            return hexlify(iv) + b"," + hexlify(ciphertext) + b"\n"

        def no_tranform(plaintext):
            return hexlify(plaintext) + b"\n"

        commands = {"SEND ENCRYPTED DATA": encrypt,
                    "SEND DATA": no_tranform}

        if len(cmd) != len("SEND ENCRYPTED DATA"):
            client_writer.write("Bob does not allow commands of length {}\n".format(len(cmd)).encode())
            return


        # We have a funny padding sheme: ignore all underscore characters
        # unpadding
        cmd = cmd.replace('_', '')

        if cmd not in commands.keys():
            client_writer.write("Unknown command `{}'. Available commands are {}\n".format(cmd, str(commands.keys())).encode())
            return

        transform = commands[cmd]
        message = transform(stored_data)
        client_writer.write("Sending data\n".encode())
        client_writer.write(message)

    except Exception as e:
        if hasattr(e.__traceback__, 'tb_lineno'):
            line = "line %s" % e.__traceback__.tb_lineno
            import traceback
            traceback.print_tb(e.__traceback__)
        else:
            line = "no traceback"
        log.error("EXCEPTION (handle connection): %s (%s) %s" % (e, type(e), line))
        try:
            error = "something went wrong with your previous message! "
            error += "Error: " + str(e) + "\n"
            client_writer.write(error.encode())
        except Exception as s:
            log.error("Exception while handling exception: %s" % s)
            return


def main():
    global stored_data
    global encryption_key

    with open('data.pdf', 'rb') as d:
        stored_data = d.read()


    # backend = default_backend()
    encryption_key = os.urandom(AES.block_size) #Random.new().read(AES.block_size)

    #start server
    loop = asyncio.get_event_loop()
    f = asyncio.start_server(accept_client, host=None, port=20005)
    log.info("Server waiting for connections")
    loop.run_until_complete(f)
    loop.run_forever()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, filename='netsec.log', format="%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s")

    # "INFO:asyncio:poll took 25.960 seconds" is annyoing
    logging.getLogger('asyncio').setLevel(logging.WARNING)

    main()
