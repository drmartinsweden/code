#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Bank
# NiceTeam
# OCT 2 2015
#

import argparse
import sys
import os.path
import socket
import signal
import re
import random
import string
import simplejson
from Crypto.Cipher import AES
import logging
import time
import decimal

PADDING = '{'
banco = {}
tarjeta = []
parser = argparse.ArgumentParser()
parser.add_argument('-s', action='store', dest='authfile', default='bank.auth', help='auth-file')
parser.add_argument('-p', action='store', dest='port', default='3000', help='Port')
parser.add_argument('--version', action='version', version='%(prog)s 1.0')
parser.add_argument('--debug', action="store_true", help="increase output verbosity")
args, unknown = parser.parse_known_args()

if args.debug:
    logging.basicConfig(level=logging.DEBUG)

reg = re.compile('[_\-\.0-9a-z]')
reg2 = re.compile('(^0)')

def arguvalidos(args, unknown):
    returnValue = True
    m = reg2.match(args.port)
    if (m):
        sys.stdout.flush()
        sys.exit(255)
    if args.port:
        try:
            port = int(args.port)
            if not (port >= 1024 and port <= 65535):
                sys.exit(-1)
        except ValueError:
            sys.exit(-1)
    if args.authfile:
        for let in args.authfile:
            m = reg.match(let)
            if m:
                next
            else:
                sys.exit(-1)
        if ((len(args.authfile) > 0) and (len(args.authfile) < 256)):
            next
        else:
            sys.exit(-1)
        temp = args.authfile.split(".")
        if (len(temp) == 1):
            temp = args.authfile.split(".")
            args.authfile = temp[0] + ".auth"
    if len(unknown) > 0:
        returnValue = False
    else:
        returnValue = True
    return returnValue
def validaauthfile(): 
    if os.path.isfile(args.authfile):
        sys.exit(-1)
    else:
	a = 1

def crearauthfile():
    archi = open(args.authfile, 'w')
    sharedkey2 = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(32))
    archi.write(sharedkey2)
    print "created"
    sys.stdout.flush()
    return sharedkey2

def fillercrypter(sharedkey, text):
    BLOCK_SIZE = 32
    PADDING = '{'
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
    paddedtext = pad(text)
    encryption_suite = AES.new(sharedkey, AES.MODE_CBC, 'This is an IV456')
    cipher_text = encryption_suite.encrypt(paddedtext)
    return cipher_text

def sigint_handler(signum, frame):
    sys.exit(-1)


def handler(sigint, frame):
    sys.exit()


def receive_signal(signum, stack):
    exit(-1)


def signal_term_handler(signal, frame):
    sys.exit(-1)


signal.signal(signal.SIGUSR1, receive_signal)
signal.signal(signal.SIGUSR2, receive_signal)
signal.signal(signal.SIGTERM, receive_signal)
signal.signal(signal.SIGINT, receive_signal)
signal.signal(signal.SIGTERM, signal_term_handler)

try:
    if arguvalidos(args, unknown) is True:
        validaauthfile()
        sharedkey = crearauthfile()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', int(args.port)))
        try:
            while True:
                s.listen(10)
                dats = []
                conn, addr = s.accept()
                try:
                    conn.settimeout(10)
                    opcion = conn.recv(2)
                    if opcion == "nw": 
                        data = conn.recv(1024)  
                        decryption_suite = AES.new(sharedkey, AES.MODE_CBC, 'This is an IV456')
                        plain_text = decryption_suite.decrypt(data).rstrip(PADDING)
                        a = simplejson.loads(str(plain_text))
                        nomb = a[0]['account']
                        balan = a[1]['initial_balance']
                        ca = a[2]['card']
                        if ca in tarjeta:
                            conn.send("No")
                        else:
                            if not nomb in banco:
                                banco[nomb] = [balan, ca]
                                print "{\"initial_balance\":"+str(a[1]['initial_balance'])+", \"account\":"+"\""+str(a[0]['account'])+"\""+"}"
                                conn.send("Si")
                                tarjeta.append(ca)
                                sys.stdout.flush()
                            else:
                                conn.send("No")
                    elif opcion == "dw": 
                        data = conn.recv(1024)
                        decryption_suite = AES.new(sharedkey, AES.MODE_CBC, 'This is an IV456')
                        plain_text = decryption_suite.decrypt(data).rstrip(PADDING)
                        a = simplejson.loads(str(plain_text))
                        nom = a[0]['account']
                        bal = a[1]['initial_balance']
                        car = a[2]['card']
                        if nom in banco:
                            if banco[nom][1] == car:
                                num1 = decimal.Decimal('%.3f' % float(bal))
                                num2 = decimal.Decimal('%.3f' % float(banco[nom][0]))
                                numtot= num1 + num2
                                banco[nom][0] = numtot
                                tp = decimal.Decimal('%.3f' % float(a[1]['initial_balance']))
                                print "{\"account\": \""+str(a[0]['account'])+"\""+","+" \"deposit\": "+str(tp)+"}"
                                sys.stdout.flush()
                                conn.send("Si")
                            else:
                                conn.send("No")
                                sys.stdout.flush()
                        else:
                            conn.send("No")
                            sys.stdout.flush()
                    elif opcion == "wd": 
                        data = conn.recv(1024)  
                        decryption_suite = AES.new(sharedkey, AES.MODE_CBC, 'This is an IV456')
                        plain_text = decryption_suite.decrypt(data).rstrip(PADDING)
                        a = simplejson.loads(str(plain_text))
                        nom = a[0]['account']
                        bal = a[1]['withdraw']
                        car = a[2]['card']
                        if banco.has_key(nom):
                            if banco[nom][1] == car:
                                tp = decimal.Decimal(bal)
                                saldoafavor = decimal.Decimal(banco[nom][0]) - tp
                                if saldoafavor >= 0:
                                    banco[nom][0] = saldoafavor
                                    print "{\"account\": \""+str(a[0]['account'])+"\""+","+" \"withdraw\": "+bal+"}"
                                    sys.stdout.flush()
                                    conn.send("Si")
                                else:
                                    conn.send("No")
                        else:
				a = 2	
                    elif opcion == "cs": 
                        dat = conn.recv(1024)
                        decryption_suite = AES.new(sharedkey, AES.MODE_CBC, 'This is an IV456')
                        plain_text2 = decryption_suite.decrypt(dat).rstrip(PADDING)
                        a = simplejson.loads(str(plain_text2))
                        nom = a[0]['account']
                        car = a[1]['card']
                        if banco.has_key(nom):
                            if car == banco[nom][1]:
                                conn.send("Si")
                                info = [{"account": nom}, {"deposit": banco[nom][0]}]
                                dati = simplejson.dumps(info)
                                a = simplejson.loads(dati)
                                balan=decimal.Decimal('%.2f' % float(a[1]['deposit']))
                                print "{\"account\":"+"\""+str(a[0]['account'])+"\", \"balance\":"+str(balan)+""+"}"
                                cipher_text = fillercrypter(sharedkey, dati)
                                conn.sendall(cipher_text)
                                sys.stdout.flush()
                        else:
                            conn.send("No")
                            sys.stdout.flush()

                    else:
                        print "protocol_error"
                        sys.stdout.flush()
                    conn.close()
                except socket.error:
                    print "protocol_error"
                    sys.stdout.flush()
        except socket as msg:
            print "protocol_error"
            sys.stdout.flush()
    else:
        sys.exit(0)  
except KeyboardInterrupt as msg:
    sys.exit(255)
except socket as msg:
    s.close
    sys.exit(255)

