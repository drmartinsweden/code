#!/usr/bin/python2.7
import socket,sys,getopt,uuid
import os.path,signal,re
import simplejson
from decimal import Decimal 
from Crypto.Cipher import AES
from Crypto.Hash import HMAC,SHA256
from Crypto import Random

reNumber = re.compile('^(0|[1-9][0-9]*)$')
reAmount = re.compile('^(0|[1-9][0-9]*)\.([0-9]{2})$')
reFilename = re.compile('^[_\-\.0-9a-z]+$')

def sendToBank(authkey,msg):
    hmacnew=HMAC.new
    # set up encryption
    sha256 = SHA256.new()
    # set up random iv
    iv = Random.new().read(16)
    # pad plaintext to AES block size
    padlength = 16 - (len(msg) % 16)
    padchar = chr(padlength)
    msg = "%s%s" % (msg,padchar*padlength)
    # set up cipher
    cipher = AES.new(authkey, AES.MODE_CBC, iv)
    # encrypt message 
    encodedmsg = iv + cipher.encrypt(msg)
    # sign with SHA256
    sig = hmacnew(authkey, encodedmsg, sha256).digest()
    signedmsg = encodedmsg + sig

    # send using tcp socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        # Connect to server and send data
        sock.connect((host, port))
        sock.sendall(signedmsg)
        # Receive data from the server and shut down
        received = sock.recv(2048)
    except IOError as err:
        sys.exit(63)
    finally:
        sock.close()
    
    # take hmac off of received message
    iv   = received[:16] 
    sig  = received[-32:]
    msg  = received[16:-32]
    iv_msg = received[:-32]    
    cipher = AES.new(authkey, AES.MODE_CBC, iv)

    # verify hmac
    if not ( hmacnew(authkey, iv_msg, sha256).digest() == sig ):
        decodedtext = "protocol_error"
    else:
        decodedtext = str(cipher.decrypt(msg))
        # remove padding
        decodedtext = decodedtext[:-ord(decodedtext[-1])]
    
    return decodedtext

# MAIN PROGRAM
if __name__ == "__main__":
    # Parse command line options
    try:
        opts, args = getopt.getopt(sys.argv[1:], "s:i:p:c:a:n:d:w:g")
        if (len(args)>0): # no separate arguments allowed
            raise ValueError
    except (getopt.GetoptError, ValueError) as err:
        sys.exit(255)

    optdict={k:v for k,v in opts} # move opts to dictionary

    if len(optdict.keys()) != len(opts): # if not equal, there were duplicates
        sys.exit(255)

    opercount=0
    try:
        port = optdict['-p']
    except:
        port = "3000"
    try:
        host = optdict['-i']
    except:
        host = "127.0.0.1"
    try:
        account = optdict['-a']
    except:
        sys.exit(255)
    if '-s' in optdict:
        authfile = optdict['-s']
    else:
        authfile = "bank.auth"
    if '-c' in optdict:
        cardfile = optdict['-c']
    else:
        cardfile=account+'.card'
    if '-n' in optdict:
        operation="new"
        amount = optdict['-n']
        opercount+=1
    if '-d' in optdict:
        operation="deposit"
        amount = optdict['-d']
        opercount+=1
    if '-w' in optdict:
        operation="withdraw"
        amount = optdict['-w']
        opercount+=1
    if '-g' in optdict:
        operation="get"
        amount="0.01" # hack
        opercount+=1

    if opercount!=1:
        sys.exit(255)

    # INPUT SANITY CHECKS
    if (reNumber.match(port)):
        port = int(port)
        if (port<1024) or (port>65535):
            sys.exit(255)
    else:
        sys.exit(255)

    if not (reAmount.match(amount)):
        sys.exit(255)
    else:
        if not (Decimal(amount)>0 and Decimal(amount)<4294967296 ):
            sys.exit(255)
        
    if not (re.match("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",host)):
        sys.exit(255)
    
    len_account = len(account)
    if not (reFilename.match(account) and len_account>0 and len_account<251):
        sys.exit(255)
    
    len_authfile = len(authfile) 
    if not (reFilename.match(authfile) and len_authfile>0 and len_authfile<256 and authfile!='.' and authfile!='..' ):
        sys.exit(255)
    else: 
        try:
            with open(authfile,"rb") as f:
                authkey=f.read(16)
        except IOError:
            sys.exit(255)
  
    len_cardfile = len(cardfile)
    if not (reFilename.match(cardfile) and len_cardfile>0 and len_cardfile<256 and cardfile!='.' and cardfile!='..' ):
        sys.exit(255)

    # New account
    if (operation=='new'):
        #check balance > 10
        if (Decimal(amount)<10):
            sys.exit(255)
        #card file must not already exist
        if os.path.isfile(cardfile):
            sys.exit(255)
        #generate unique card number
        cardno = str(uuid.uuid1())
        data = {'operation':operation, 'account':account, 'cardno':cardno, 'balance':amount}
        datajson = simplejson.dumps(data)

    # Deposit, Withdraw or Get
    if (operation in ["withdraw", "deposit", "get"]):
        if not os.path.isfile(cardfile):
            sys.exit(255)
        card_file = open(cardfile, "r")
        cardno=card_file.read()
        card_file.close()
        data = {'operation':operation, 'account':account, 'cardno':cardno, 'amount':amount}
        datajson = simplejson.dumps(data)

    # send request to server and receive response
    received = sendToBank(authkey,datajson)

    if (received == "FAILED"):
        sys.exit(255)
    elif (received == "protocol_error"):
        sys.exit(63)

    # code does not reach here when failure or protocol error is received
    if operation == "new":
        #write card file now
        card_file = open(cardfile, "w")
        card_file.write("%s" % cardno)
        card_file.close()
    print received
    sys.stdout.flush()

