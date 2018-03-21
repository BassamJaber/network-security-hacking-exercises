#!/usr/bin/env python3
 
import random
import asyncio
import logging
import concurrent.futures
import math
from binascii import hexlify, unhexlify


log = logging.getLogger(__name__)
clients = {}  # task -> (reader, writer)

stored_data = None
random_string = None
 
 
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
            log.info("client terminated")
            return None
        try:
            data = yield from asyncio.wait_for(client_reader.readline(), timeout=30.0)
        except concurrent.futures.TimeoutError:
            #log.info("timeout")
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
    ip_hash = None
    try:
        remote = client_writer.get_extra_info('peername')
        if remote is None:
            log.error("Could not get ip of client")
            return
        ip_hash= hash(remote[0]) # not cryptographical
        remote = "%s:%s" % (remote[0], remote[1])
        log.info("new connection from: %s" % remote)
    except Exception as e:
        log.error("EXCEPTION (get peername): %s (%s)" % (e, type(e)))
        return

    #password for root based on ip
    random_part =  (int(math.fabs(ip_hash)) + int(random_string)) % 100 #lol
    credentials = "root,Password"+str(random_part).zfill(2)  # text message format: root,Password

    try:
        #get client credentials (username,password)
        client_credentials = yield from read_line_safe(client_reader)
        #create challenge
        challenge = generate_challenge()
        #calculate challenge solution
        challenge_solution = str(eval(challenge))
        #send challenge to client
        client_writer.write("{}\n".format(challenge).encode())

        #wait for response
        challenge_answer = yield from read_line_safe(client_reader)


        if client_credentials is None or challenge_answer is None:
            log.warning("did not get credentials or challenge answer")
            return

        if not ',' in client_credentials:
            client_writer.write("Invalid credentials format (should be username,password)!\n".encode())
            return

        #check for incorrect arguments
        if challenge_solution != challenge_answer:
            error="Wrong answer to challenge: `{}'; correct answer: `{}'\n".format(challenge_answer, challenge_solution)
            client_writer.write(error.encode())
            return
        elif client_credentials.split(',')[0] != credentials.split(',')[0]:
            client_writer.write("Unknown Username\n".encode())
            return
        elif client_credentials.split(',')[1] != credentials.split(',')[1]:
            error="Invalid Password `{}'\n".format(client_credentials.split(',')[1])
            client_writer.write(error.encode())
            return
        else:
            client_writer.write("login successful\n".encode())
            log.info("success: {} {}".format(client_credentials, remote))
            client_writer.write(stored_data)

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

def generate_challenge():
    operators=["+","-","*"]
    res=str(random.randint(1,20))
    for i in range(random.randint(4,6)):
        res+=operators[random.randint(0,2)]+str(random.randint(1,20))
    return res

def main():
    global stored_data
    global random_string
    
    with open('data.pdf', 'rb') as d:
        stored_data = d.read()

    stored_data = hexlify(stored_data)

    random_string = str(random.randint(1000,200000))

    #start server
    loop = asyncio.get_event_loop()
    f = asyncio.start_server(accept_client, host=None, port=20002)
    log.info("Server waiting for connections")        
    loop.run_until_complete(f)
    loop.run_forever()


 
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, filename='netsec02.log', format="%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s")

    # "INFO:asyncio:poll took 25.960 seconds" is annyoing
    logging.getLogger('asyncio').setLevel(logging.WARNING)

    main()
