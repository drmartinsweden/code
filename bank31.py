#!/usr/bin/python2.7
import socket
import sys,getopt
import os.path,signal,simplejson
from decimal import Decimal
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC
from Crypto import Random

rndfile = Random.new()

# Client Connection Handler
def handle(clientsock):
    global accounts
    hmacnew=HMAC.new
    response="FAILED"  # should anything go wrong anywhere, the defaul response is FAILED
    protocol_ok = True
    # set up encryption
    sha256 = SHA256.new()
    # receive data from client 
    try:
        data = clientsock.recv(2048)
    except socket.timeout:
        response="protocol_error"
        protocol_ok = False
        
    if protocol_ok:
        # strip HMAC and IV off of message
        sig = data[-32:]
        msg = data[16:-32]
        iv  = data[:16]
        iv_msg = data[:-32]
        # set up cipher and verify hmac
        try:
            cipher = AES.new(authkey, AES.MODE_CBC, iv)
            protocol_ok = (hmacnew(authkey, iv_msg, sha256).digest() == sig)
            if not protocol_ok: response="protocol_error"
        except:
            response="protocol_error"
            protocol_ok = False
        
    if protocol_ok:
        decodedtext = str(cipher.decrypt(msg))
        # remove padding
        decodedtext = decodedtext[:-ord(decodedtext[-1])]
        # load received json message to data
        try:
            jdata = simplejson.loads(decodedtext)
            operation=str(jdata['operation'])
        except ValueError:
            operation=None
            response="protocol_error"

        if (operation=="new"):
            account = str(jdata['account'])
            balance = Decimal(jdata['balance'])
            cardno  = str(jdata['cardno'])

            if not account in accounts :
                accounts[account] = [balance,cardno]
                response=simplejson.dumps( {'account':account, 'initial_balance':balance} )

        if (operation in ["withdraw", "deposit", "get"]):
            account = str(jdata['account'])
            amount  = Decimal(jdata['amount'])
            reqcardno = str(jdata['cardno'])

            if account in accounts:
                accbalance, acccardno =  accounts[account]
                if acccardno==reqcardno:
                    if operation=="deposit":
                        accbalance = accbalance + amount
                        accounts[account] = [accbalance,acccardno]
                        response=simplejson.dumps( {'account':account, 'deposit':amount} )
                    elif operation=="withdraw":
                        if amount <= accbalance:
                            accbalance = accbalance - amount
                            accounts[account] = [accbalance,acccardno]
                            response=simplejson.dumps( {'account':account, 'withdraw':amount} )
                    elif operation=="get":
                        response=simplejson.dumps( {'account':account, 'balance':accbalance} )

    if not response=="FAILED":
        print response
        sys.stdout.flush()
        
    # add padding to response
    padlength = 16 - (len(response) % 16)
    padchar = chr(padlength)
    response = "%s%s" % (response,padchar*padlength)
    
    iv = rndfile.read(16)
    cipher = AES.new(authkey, AES.MODE_CBC, iv) 
    msg = cipher.encrypt(response)
    sig = hmacnew(authkey, iv + msg, sha256).digest()
    clientsock.send(iv + msg + sig)
    clientsock.close()
    return
# end TCP Handler

# Exit cleanly when receive SIGTERM 
def sigHandler(signum, frame):
    global server_running
    server_running = False
    return

signal.signal(signal.SIGTERM, sigHandler)
signal.signal(signal.SIGINT, sigHandler)

# MAIN PROGRAM
if __name__ == "__main__":
    host, port = "", 3000
    authfile   = "bank.auth"
    optflags   = {'-p':False, '-s':False}
    accounts={}
    server_running = True
    
    # Parse command line options
    try:
        opts, args = getopt.getopt(sys.argv[1:], "p:s:")
    except getopt.GetoptError as err:
        sys.exit(255)
    for o, a in opts:

        # Check for duplicates, because getopt allows them
        if (optflags[o]):
            sys.exit(255)
        optflags[o]=True

        if o == "-p":
          try:
            port = int(a)
            if (port<1024) or (port>65535):
              raise ValueError
          except ValueError:
            sys.exit(255)
        elif o == "-s":
            authfile = a

    if os.path.isfile(authfile):
        # file already exists
        sys.exit(255)
   
    # Generate AES key and write to auth-file 
    try:
        authkey = rndfile.read(16) # 128-bit key for AES
        auth_file = open(authfile, "wb")
        auth_file.write(authkey)
        auth_file.close()
    except IOError:
        sys.exit(255)
 
    # Create the server
    serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serversock.bind((host, port))
    serversock.listen(1)

    print "created"
    sys.stdout.flush()

    while server_running:
        try:
            conn, addr = serversock.accept()
            conn.settimeout(10)
            handle(conn)
        except:
            server_running=False
    
    serversock.close()
    sys.exit(0)

