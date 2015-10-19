#!/usr/bin/python -u

'''
#   #!/home/bibi/working_repo/capstone/env/bin/pypy -u
'''

import sys, os, getopt, socket, threading, SocketServer, signal
import time
import pickle
import os
from cryptography.fernet import Fernet
import base64
import hmac
import hashlib
import re
import argparse
#import traceback
import struct

class AtmTransaction:
     def __init__(self, op="", account="", pin="", amount=0L, status=""):
        self.op = op
        self.account = account
        self.pin = pin
        self.amount = amount
        self.status = status


# Method to read the bank.auth file
def read_logtime_file(logTimefile):
    with open(logTimefile, "r") as file:
         token=file.readline()
    return float(token)

# Method to read the bank.auth file
def addtime_logtime_file(logTimefile, timeToAdd):
    pass
    '''
    logTimefile = "/home/bibi/working_repo/test/testTime/" + logTimefile
    currentTime = read_logtime_file(logTimefile)
    with open(logTimefile, "w") as file:
        file.write(str(currentTime+timeToAdd) + '\n')
        file.flush()
    '''

class ThreadedTCPRequestHandler(SocketServer.BaseRequestHandler):
    # Method to handle a client which connected to the server
    def handle(self):
        self.request.settimeout(10)
        received_data = ""
        try:
            starttime = time.time()
            self.authenticate()
            addtime_logtime_file('auth.time', (time.time() - starttime))
            buff = self.request.recv(1024)
            #starttime = time.time()
            #f = Fernet(base64.urlsafe_b64encode(g_cryptokey))
            #data = f.decrypt(buff,20)
            #addtime_logtime_file('cypher.time', (time.time() - starttime))
            starttime = time.time()
            response = process_raw_atm_transaction(buff)
            addtime_logtime_file('exec_cmd.time', (time.time() - starttime))
            #starttime = time.time()
            #self.request.sendall(f.encrypt(pickle.dumps(response)))
            self.request.sendall(pickle.dumps(response))
            #addtime_logtime_file('cypher.time', (time.time() - starttime))
        except Exception as e:
            print "protocol_error"
            #print '-'*60
            #traceback.print_exc(file=sys.stdout)
            #print '-'*60

        finally:
            l_onoff = 1
            l_linger = 0
            self.request.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger))
            self.request.close()


    def authenticate(self):
        global g_cryptokey
        global g_authFile
        r1 = self.request.recv(1024)
        r2 = os.urandom(32)
        self.request.sendall(r2)
        response = self.request.recv(1024)
        token=read_auth_file(g_authfile)
        challenge=hmac.new(token, r1+r2, hashlib.sha256).hexdigest()
        # PBKDF2 can be used here instead of this:
        #g_cryptokey = hmac.new(token, r1+r2+"1", hashlib.sha256).digest()
        self.request.sendall(challenge)
        if not (hmac.compare_digest(hmac.new(token, r2+r1, hashlib.sha256).hexdigest(), response)):
            raise Exception
        return

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


class ServerState:
    def __init__(self):
        self.isrunning = 0

##
 #Global variable in order to count number of times and option apperas
 #e.g atm -s auth1.auth -s auth2.auth
##
class ArgContBank(object):
    def __init__(self):
        self.file_auth = 0
        self.port_number = 0

b=ArgContBank()

##
 #Patterns, regexp
##
pattern_auth_file = re.compile('[_\-\.0-9a-z]+')
pattern_number = re.compile('(0|[1-9][0-9]*)')

##
 #Defs, in order to sanitize inputs
##
def file_auth(string):
    b.file_auth+=1
    if b.file_auth == 2:
        raise ValueError()
    else:
        fileName = pattern_auth_file.match(string)
        if (fileName) and (len(string)<256) and (string != '.') and (string != '..') and (len(fileName.group(0)) == len(string)):
            return string
        else:
            raise ValueError()

def port_number(string):
    b.port_number+=1
    if b.port_number == 2:
        raise ValueError()
    else:
        portNumber = pattern_number.match(string)
        if ((portNumber) and (len(string) == len(portNumber.group(0))) and (int(portNumber.group(0))>1023) and (int(portNumber.group(0))<65536)):
            return int(portNumber.group(0))
        else:
            raise ValueError()


global balance
global pin
global server_state
global g_cryptokey
global g_authfile

# Method to print the usage of the bank program
def usage():
    print('Usage: bank.py [-p portNumber] [-s bankAuthFile]')
    exit(255)


# Method to create / read the auth-file
def create_auth_file(filename):
    with open(filename, "w") as file:
        token = os.urandom(32)
        file.write(token)
    print 'created' # Spec requirement

def read_auth_file(filename):
    with open(filename, "r") as file:
        token = file.read(32)
    return token


# Allowed operations
ops = ["NEW", "GET", "WIT", "DEP"]

def process_amount_to_string(amount):
    dec=long(amount)%100
    floatingpart = ""
    if (dec > 0):
        floatingpart = "."
        if (dec>9):
            floatingpart += str(dec)
        elif (dec>0):
            floatingpart += "0" + str(dec)
    return str((long(amount)-dec)/100L) + floatingpart

def process_raw_atm_transaction(rawdata):
    try:
        transaction = pickle.loads(rawdata)
    except:
        raise Exception

    if (transaction.op not in ops):
        return

    elif (transaction.op == "NEW"):
        if (balance.has_key(transaction.account)):
            transaction.status="ERROR"
        elif (transaction.pin in set(pin.values())):
            transaction.status="ERROR"
        else:
            balance[transaction.account] = long(transaction.amount)
            pin[transaction.account] = transaction.pin
            transaction.status="OK"
            print('{\"initial_balance\": %s, \"account\": \"%s\"}' % (process_amount_to_string(transaction.amount), transaction.account))
        return transaction

    elif (transaction.op == "GET"):
        if (balance.has_key(transaction.account) == False) or \
           (pin[transaction.account] != transaction.pin):
                transaction.status = "ERROR"
        else:
            transaction.status="OK"
            transaction.amount=balance[transaction.account]
            print('{\"account\": \"%s\", \"balance\": %s}' % (transaction.account, process_amount_to_string(transaction.amount)))
        return transaction

    elif (transaction.op == "WIT"):
        if (balance.has_key(transaction.account) == False) or \
        (pin[transaction.account] != transaction.pin) or \
        (balance[transaction.account] < transaction.amount):
            transaction.status="ERROR"
        else:
            transaction.status="OK"
            balance[transaction.account] = (balance[transaction.account] - long(transaction.amount))
            print('{\"account\": \"%s\", \"withdraw\": %s}' % (transaction.account, process_amount_to_string(transaction.amount)))
        return transaction

    elif (transaction.op == "DEP"):
        if (balance.has_key(transaction.account) == False) or \
        (pin[transaction.account] != transaction.pin):
            transaction.status="ERROR"
        else:
            transaction.status="OK"
            balance[transaction.account] = (balance[transaction.account] + long(transaction.amount))
            print('{\"account\": \"%s\", \"deposit\": %s}' % (transaction.account, process_amount_to_string(transaction.amount)))
        return transaction


def signal_handler(signum, frame):
    server_state.isrunning = 0

if (__name__ == "__main__"):

    try:

        ##
         #Argument Parser Setup
        ##
        parser = argparse.ArgumentParser(usage=False, add_help=False)

        #[-s <auth-file>] DEFAULT:bank.auth
        parser.add_argument('-s', dest='authFile', default='bank.auth', type=file_auth)
        #[-p <port>] DEFAULT:3000
        parser.add_argument('-p', dest='portNumber', default='3000', type=port_number)

        args = parser.parse_args()

        # Handle signals
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

        create_auth_file(args.authFile)

        # Dictionaries to manage balances and pin
        balance = dict()
        pin = dict()

        g_authfile = args.authFile

        # We listen on all the interfaces
        listening_addr = "0.0.0.0"

        server_error = 0
        try:
            ThreadedTCPServer.allow_reuse_address = True
            server = ThreadedTCPServer((listening_addr, args.portNumber), ThreadedTCPRequestHandler)
            server_state = ServerState()
            server_state.isrunning = 1
            # Start a thread with the server -- that thread will then start one
            # more thread for each request
            server_thread = threading.Thread(target=server.serve_forever)
            # Exit the server thread when the main thread terminates
            server_thread.daemon = True
            server_thread.start()

            while server_state.isrunning != 0:
                time.sleep(1)

        except:
            server_error = 1
            raise
        finally:
            server.shutdown()
            server_thread.join()
            server.server_close()
            if (server_error == 0):
                sys.exit(0)
            else:
                raise

    except:
        exit(255)
