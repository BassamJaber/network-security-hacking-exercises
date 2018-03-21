#!/usr/bin/env python3
 
import random
import asyncio
import logging
import concurrent.futures
from binascii import hexlify, unhexlify
from Crypto.PublicKey import RSA



log = logging.getLogger(__name__)
clients = {}  # task -> (reader, writer)

stored_data = None

#4096 secure key, do not brute force!
pubkey_string = """-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0nHGpUDrvNW27N1g09W+
aQYVQJyEx8u0DWw5+iYilzPJXw7i8+XQXngl+glsyUrWvP0CPm23HBpqQ9fPwZp4
8hzdqonBGa8ne2Eph746uvhSWoX+IsHUEGuqaGkqxpyo/arXXBP6UnkNIRybU0pP
ldXSTjRjVc/JhFEfOLVajVq92aMgWkuSfBhVqJCr76OC0S111s/s7qJRe5PVAGcT
RxKM8PcFv5MnXMy4qglZBVKyKo5kpCwdH7fV0AoL2T8sCJFAGyfV8c8V73dRpwRq
u8FHWHEPGfQ8ag4IrAsj6VF3r6epxFGDepER7tanOTy+k9EMOVUV3y4xpt23jGYe
MZN/4cp8fvaGYrPpbKXoIyNObZ8cUepzuKzXpSk0zN06qR7uGXXj5mE0tJx2ZIE+
Gf93uvisXgJlCcHMjvTKWiqY81K1e5+l3Xb+cEkIgcjF1Yrns0wPiM9QwSfFZeGC
tYIxFtQ0q+8jMX2fVBsQDPPZneGSD22nP9JVAsadYle3BsNR2Qzs5Eq9X3v3plZe
FzoKr1WC7kpC4EcNjqrKme2JS8vGl9qZJLVN71ix6Vl8R3iO1hhgiVotWLGEDzYa
eKeSdodyP+uTh7HyjlFkWXr2RlqwvN/tOO8RnfZaz67FQkccW/pTtpAwUiL6DGzD
PYhmIBv7bK3WfQrB8qF0268CAwEAAQ==
-----END PUBLIC KEY-----"""
pubkey = None #imported public key


def string_to_number(string):
    assert isinstance(string, str)
    n = 0
    for c in string:
        n = n << 8
        n += ord(c)
    return n

def number_to_string(number):
    assert isinstance(number, int)
    s = []
    while number:
        c = chr(number & 0xff)
        s.append(c)
        number = number >> 8
    return "".join(reversed(s))

assert number_to_string(string_to_number("foobar")) == "foobar"
assert number_to_string(string_to_number("Hello World")) == "Hello World"
assert number_to_string(string_to_number("")) == ""
assert string_to_number("") == 0 

def sign(key, message):
    assert isinstance(message, str)
    
    #from help(RSA), where the key.sign method is located
    """sign(M, K) method of Crypto.PublicKey.RSA._RSAobj instance
        Sign a piece of data with RSA.
        
        Signing always takes place with blinding.
        
        :attention: this function performs the plain, primitive RSA decryption
         (*textbook*). In real applications, you always need to use proper
         cryptographic padding, and you should not directly sign data with
         this method. Failure to do so may lead to security vulnerabilities.
         It is recommended to use modules
         `Crypto.Signature.PKCS1_PSS` or `Crypto.Signature.PKCS1_v1_5` instead.
        
        :Parameter M: The piece of data to sign with RSA. It may
         not be numerically larger than the RSA module (**n**).
        :Type M: byte string or long
        
        :Parameter K: A random parameter (*for compatibility only. This
         value will be ignored*)
        :Type K: byte string or long
        
        :Return: A 2-item tuple. The first item is the actual signature (a
         long). The second item is always None.
    """
    return key.sign(string_to_number(message), None)[0]


def verify(key, message, signature):
    assert isinstance(message, str)
    assert isinstance(signature, int)
    return key.verify(string_to_number(message), (signature, None))


 
 
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

    try:
        ## interesting stuff starts here
        client_command = yield from read_line_safe(client_reader)
        
        if not client_command:
            return
        
        if not ',' in client_command or len(client_command.split(',')) != 2:
            client_writer.write("Invalid client_command. Syntax is: command,signature\n".encode())
            return
        
        client_command, signature = client_command.split(',')
        
        try:
            signature = int(signature)
        except ValueError as e:
            client_writer.write("signature must be an int.\n".encode())
            return
            
        if not verify(pubkey, client_command, signature):
            client_writer.write("signature verification failed.\n".encode())
            return
        
        if client_command == "no pdf!":
            client_writer.write("k thx bye\n".encode())
        else:
            client_writer.write("dumping you a pdf\n".encode())
            client_writer.write(stored_data)
            
        ## interesting stuff ends here
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
    global pubkey
    
    with open('data.pdf', 'rb') as d:
        stored_data = d.read()

    stored_data = hexlify(stored_data)

    pubkey = RSA.importKey(pubkey_string)
    try:
        pubkey.sign("foobar", None)
    except TypeError as e:
        print("We only have a public key. We cannot sign: `{}'".format(e))
    
    print("But we can verify!")
    assert verifyverify(pubkey, "no pdf!", 163500588565413589352223629993702135739553077726756675440483306149798655204198344843331760510195175146814283361544599092537829135392507095081189793305633877579801872353570978891656895873906720972156496510294340234516526820409601201157470113610776283535313672719914216998384589074577810712618749784654963164457298206679206106288451467218119111005586799354808981113680264987046206060750257686647037454085439353822993257283049011391575445877432910796187683784616135184038509000623975847726989176467768485894080202764047363760247366252679311291290712778367908272395456305424135780083973483881490048487013709681486797990575776687556570657434895936063064352824902751797801367588761683002308814083687035474716660147561280405061360257233050146356452363141796331668985248692662663373288645919871965565565752700763707034371541411984117066914044048705284982729782635634074397342268292712457694540587289705144940586268178864341401905889979409923989232901952003847076681021756685359762635857287343475290926048910152860823823992991796090710432322569811067679084747310572870435102855208492631791174093531156354615739783278886214373856469832863381039009300322074397167027094058668629821721593192632219014070329502647086443400117444386018037360999824)


    #start server
    loop = asyncio.get_event_loop()
    f = asyncio.start_server(accept_client, host=None, port=20009)
    log.info("Server waiting for connections")        
    loop.run_until_complete(f)
    loop.run_forever()


 
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, filename='netsec.log', format="%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s")

    # "INFO:asyncio:poll took 25.960 seconds" is annyoing
    logging.getLogger('asyncio').setLevel(logging.WARNING)

    main()
