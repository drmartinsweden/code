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
import string
import random
import re
import simplejson
from Crypto.Cipher import AES
import os
import logging
import decimal

PADDING = '{'

reg = re.compile('[_\-\.0-9a-z]')
reg2 = re.compile('\.{2}')
reg3 = re.compile('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
reg4 = re.compile('(^0)')
reg5 = re.compile('[_\-\.0-9]')

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

parser = argparse.ArgumentParser()
parser.add_argument('-s', action='store', dest='authfile', default='bank.auth', help='auth-file')
parser.add_argument('-p', action='store', dest='port', default='3000', help='Port')
parser.add_argument('-a', action='store', dest='account', help='account', required=True)
parser.add_argument('-i', action='store', dest='ip', default='127.0.0.1', help='IP')
parser.add_argument('-c', action='store', dest='card', help='card-file')
parser.add_argument('--version', action='version', version='%(prog)s 1.0')

parser.add_argument('-n', action='store', dest='new', help='create-balance')
parser.add_argument('-d', action='store', dest='amount', help='amount')
parser.add_argument('-w', action='store', dest='withd', help='withdraw')
parser.add_argument('-g', action='append_const', dest='curr',const='', help='current-balance')
parser.add_argument('--debug', action="store_true", help="increase output verbosity")
try:
    args, unknown = parser.parse_known_args()
except SystemExit:
    sys.exit(-1)

if args.debug:
    logging.basicConfig(level=logging.DEBUG)

if args.curr is not None:
    if len(args.curr) >= 2 :
        sys.exit(-1)
else:
    a = 1

def newaccount(nom, card, sal):
    temp = sal.split(".")
    if (temp[0]):
        if (temp[0].isdigit()):
            if (len(temp[0]) > 1):
                m = reg4.match(temp[0])
                if (m):
                    sys.stdout.flush()
                    sys.exit(255)
                else:
                    if (len(temp) == 1):
                        sys.stdout.flush()
                        sys.exit(255)
                    else:
                        if (temp[1]):
                            if (temp[1].isdigit()):
                                if (len(temp[1]) > 2):
                                    sys.stdout.flush()
                                    sys.exit(255)
                                if (len(temp[1]) > 1):
                                    if (m):
                                        sys.stdout.flush()
                                        sys.exit(255)
                                else:
                                    sys.stdout.flush()
                                    sys.exit(255)
                            else:
                                sys.stdout.flush()
                                sys.exit(255)
                        else:
                            sys.stdout.flush()
                            sys.exit(255)
                        if (sal > 10):
                            temp = [{"account": nom}, {"initial_balance": sal}, {"card": card}]
                            info = [{"account": nom}, {"initial_balance": sal}]
                            json1 = simplejson.dumps(info)
                            json2 = simplejson.dumps(temp)
                            return json1, json2
                        else:
                            sys.stdout.flush()
                            sys.exit(255)
            else:
                if (int(temp[0]) >= 0):
                    if (float(sal) > 10):
                        temp = [{"account": nom}, {"initial_balance": sal}, {"card": card}]
                        info = [{"account": nom}, {"initial_balance": sal}]
                        json1 = simplejson.dumps(info)
                        json2 = simplejson.dumps(temp)
                        return json1, json2
                    else:
                        sys.stdout.flush()
                        sys.exit(255)
        else:
            sys.stdout.flush()
            sys.exit(255)
    else:
        print "saliendo"



def deposito(nom, card, sal):
    try:
        if (float(sal) > 4294967295.999):
            sys.exit(255)
    except ValueError:
        sys.exit(255)
    temp = sal.split(".")
    if (temp[0]):
        if (temp[0].isdigit()):
            if (len(temp[0]) > 1):
                m = reg4.match(temp[0])
                if (m):
                    sys.stdout.flush()
                    sys.exit(255)
                else:
                    if (len(temp) == 1):
                        sys.stdout.flush()
                        sys.exit(255)
                    else:
                        if (temp[1]):
                            if (temp[1].isdigit()):
                                if (len(temp[1]) > 2):
                                    sys.stdout.flush()
                                    sys.exit(255)
                                if (len(temp[1]) > 1):
                                    if (m):
                                        sys.stdout.flush()
                                        sys.exit(255)
                                else:
                                    sys.stdout.flush()
                                    sys.exit(255)
                            else:
                                sys.stdout.flush()
                                sys.exit(255)
                        else:
                            sys.stdout.flush()
                            sys.exit(255)
                        if (sal > 10):
                            temp = [{"account": nom}, {"initial_balance": sal}, {"card": card}]
                            info = [{"account": nom}, {"initial_balance": sal}]
                            json1 = simplejson.dumps(info)
                            json2 = simplejson.dumps(temp)
                            return json1, json2
                        else:
                            sys.stdout.flush()
                            sys.exit(255)
            else:
                if (int(temp[0]) >= 0):
                    if (float(sal) > 0):
                        sal = decimal.Decimal('%.2f' % float(sal))
                        temp = [{"account": nom}, {"initial_balance": sal}, {"card": card}]
                        info = [{"account": nom}, {"initial_balance": sal}]
                        json1 = simplejson.dumps(info)
                        json2 = simplejson.dumps(temp)
                        return json1, json2
                    else:
                        sys.stdout.flush()
                        sys.exit(255)
        else:
            sys.stdout.flush()
            sys.exit(255)
    else:
        print "saliendo"

def retiro(nom, card, sal):
    car = card.split(".")
    if (car[0] != nom):
        sys.exit(255)	
    if ( float(sal) > 0):
        temp = [{"account": nom}, {"withdraw": sal}, {"card": card}]
        info = [{"account": nom}, {"withdraw": sal}]
        json1 = simplejson.dumps(info)
        json2 = simplejson.dumps(temp)
        return json1, json2
    else:
        sys.exit(255)
def saldo(nom, card):
    car = card.split(".")
    if (car[0] != nom):
        sys.exit(255)	
    temp = [{"account": nom}, {"card": card}]
    info = [{"account": nom}, {"card": card}]
    json1 = simplejson.dumps(info)
    json2 = simplejson.dumps(temp)
    return json1, json2


def valaccount(acc):
    for let in acc:
        m = reg.match(let)
        if m:
            next
        else:
            sys.exit(255)
    if ((len(acc) > 0) and (len(acc) < 251)):
        next
    else:
        sys.exit(255)


def valcard(card, acct):
    if ( len(card) > 255 ):
        sys.exit(255)
    car = card.split(".")
    if (car[0]):
        m = reg2.match(card)
        if m:
            sys.stdout.flush()
            sys.exit(255)
        else:
            tm = reg5.match(car[0])
            if (tm):
                sys.stdout.flush()
                sys.exit(255)
            else:
                for let in car[0]:
                    m = reg5.match(let)
                    if m:
                        sys.exit(255)
                    else:
                        next
                return args.card
    else:
        sys.stdout.flush()
        sys.exit(255)


def valauth(auth):
    for let in auth:
        m = reg.match(let)
        if m:
            next
        else:
            sys.exit(255)
    if (len(auth) > 0) and (len(auth) < 256):
        next
    else:
        sys.exit(260)
    temp = auth.split(".")
    if len(temp) == 1:
        temp = auth.split(".")
        args.authfile = temp[0] + ".auth"
        if not os.path.isfile(args.authfile):
            sys.exit(255)
        else:
            next
    else:
        if not os.path.isfile(args.authfile):
            sys.exit(255)
        else:
            next

def llencard(card):
    args.card = args.account + ".card"
    return args.card


def arguvalidos(args, unknown):
    if args.port:
        m2 = reg4.match(args.port)
        if (m2):
            sys.stdout.flush()
            sys.exit(255)
        try:
	    port = int(args.port)
            if not (port >= 1024 and port <= 65535):
                sys.exit(255)
        except ValueError:
            sys.exit(-1)
    if args.ip:
        temp = reg3.match(args.ip)
        if temp:
            next
        else:
            sys.exit(255)
    if args.authfile:
        valauth(args.authfile)
    if args.account:
        valaccount(args.account)
    if args.card:
        valcard(args.card, args.account)
    else:
        llencard(args.card)
    if args.curr:
        if args.curr is '':
            sys.exit(255)
    if len(unknown) > 0:
        sys.exit(255)
    tmp = (args.new, args.amount, args.withd, args.curr)

    if (tmp[0] is not None) and (tmp[1] is None) and (tmp[2] is None) and (tmp[3] is None):
        opc = "nw"
        pant, banco = newaccount(args.account, args.card, args.new)
    elif (tmp[0] is None) and (tmp[1] is not None) and (tmp[2] is None) and (tmp[3] is None):
        opc = "dw"
        pant, banco = deposito(args.account, args.card, args.amount)
    elif (tmp[0] is None) and (tmp[1] is None) and (tmp[2] is not None) and (tmp[3] is None):
        opc = "wd"
        pant, banco = retiro(args.account, args.card, args.withd)
    elif (tmp[0] is None) and (tmp[1] is None) and (tmp[2] is None) and (tmp[3] is not None):
        opc = "cs"
        pant, banco = saldo(args.account, args.card)
    elif (tmp[0] is None) and (tmp[1] is None) and (tmp[2] is None) and (tmp[3] is None):
        sys.exit(255)
    else:
        s.close
        sys.exit(255)

    return pant, banco, opc


def crearauthfile(size=20, chars=string.ascii_uppercase + string.digits):
    archi = open(args.authfile, 'w')
    archi.write(''.join(random.choice(chars) for _ in range(size)))
    return(''.join(random.choice(chars) for _ in range(size)))


def fillercrypter(sharedkey, text):
    BLOCK_SIZE = 32
    PADDING = '{'
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
    paddedtext = pad(text)
    encryption_suite = AES.new(sharedkey, AES.MODE_CBC, 'This is an IV456')
    cipher_text = encryption_suite.encrypt(paddedtext)
    return cipher_text


def getsharedkey(authfile):
    archi = open(authfile, 'r')
    sharedkey2 = archi.read()
    return sharedkey2

def contobank(ip, port, texto, texto1, opci):
    try:
        s = socket.create_connection((ip, int(port)),10)
        s.settimeout(10)
        sharedkey = getsharedkey(args.authfile)
        if opci == "cs":
            s.send(opci)
            cipher_tex = fillercrypter(sharedkey, texto1)
            a = simplejson.loads(texto1)
            s.send(cipher_tex)
            tex = s.recv(2)
            if tex == "No":
                s.close()
                sys.exit(255)
            else:
                sys.stdout.flush()
                texs = s.recv(1024)
                decryption_suite = AES.new(sharedkey, AES.MODE_CBC, 'This is an IV456')
                plain_text2 = decryption_suite.decrypt(texs).rstrip(PADDING)
                ab = simplejson.loads(str(plain_text2))
                asd = decimal.Decimal('%.2f' % float(ab[1]['deposit']))
                print "{\"account\": \""+str(ab[0]['account'])+"\", \"balance\": "+str(asd)+"}"
                sys.stdout.flush()
                s.close()
                sys.exit(0)
        else:
            s.send(opci)
            cipher_text = fillercrypter(sharedkey, texto1)
            a = simplejson.loads(texto1)
            s.send(cipher_text)
            if (s.recv(4) == "Si"):
                if (opci == "nw"):
                    print "{\"initial_balance\":"+str(a[1]['initial_balance'])+", \"account\":"+"\""+str(a[0]['account'])+"\""+"}"
                    sys.stdout.flush()
                    sys.exit(0)
                if (opci == "dw"):
                    tp = decimal.Decimal('%.3f' % float(a[1]['initial_balance']))
                    print "{\"account\": "+"\""+str(a[0]['account'])+"\""+", \"deposit\": "+str(tp)+"}"
                    sys.stdout.flush()
                    sys.exit(0)
                if (opci == "wd"):
                    tp = decimal.Decimal('%.3f' % float(a[1]['withdraw']))
                    print "{\"account\": "+"\""+str(a[0]['account'])+"\""+", \"withdraw\": "+str(tp)+"}"
                    sys.stdout.flush()
                    sys.exit(0)
                if (opci == "cs"):
                    print "{\"balances\":"+str(a[1]['initial_balance'])+", \"account\":"+str(a[0]['account'])+"}"
                    sys.stdout.flush()
                    sys.exit(0)
            else:
                sys.exit(255)
            s.close()
            sys.exit(255)
    except Exception as msg:
        sys.exit(63)

a, b, opc = arguvalidos(args, unknown)
contobank(args. ip, args. port, a, b, opc)    

