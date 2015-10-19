#!/usr/bin/python -u

'''
#  #!/home/bibi/working_repo/capstone/env/bin/pypy -u
'''
import sys, os, re, socket, pickle, hmac, hashlib, struct, argparse
#import datetime,
#import time
#from cryptography.fernet import Fernet
#import base64


#
 #Command line validation
 #Class in order to count number of times and option appears
 #e.g atm -s auth1.auth -s auth2.auth
##
class ArgAtm(object):
    def __init__(self):
        self.file_auth = 0
        self.file_card = 0
        self.account_name = 0
        self.ip_address = 0
        self.port_number = 0
        self.account_balance = 0
        self.deposit_amount = 0
        self.withdraw_amount = 0
        self.flagInputComb = 0

#Command line validation
c=ArgAtm()

global g_cryptokey

##
 #Command line validation
 #Patterns, regexp
##
pattern_name = re.compile('[_\-\.0-9a-z]+')
pattern_auth_file = re.compile('[_\-\.0-9a-z]+')
pattern_card_file = re.compile('[_\-\.0-9a-z]+')
pattern_number = re.compile('(0|[1-9][0-9]*)')
pattern_ip = re.compile('(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
pattern_float = re.compile('^(0|[1-9][0-9]*)\.[0-9]{2}$')

##
 #Command line validation
 #Defs, in order to sanitize inputs
##
def file_auth(string):
    c.file_auth+=1
    if c.file_auth == 2:
        raise
    else:
        fileName = pattern_auth_file.match(string)
        if (fileName) and (len(string)<256) and (string != '.') and (string != '..') and (len(fileName.group(0)) == len(string)):
            return string
        else:
            raise

def file_card(string):
    c.file_card+=1
    if c.file_card == 2:
        raise
    else:
        fileName = pattern_card_file.match(string)
        if (fileName) and (len(string)<256) and (string != '.') and (string != '..') and (len(fileName.group(0)) == len(string)):
            return string
        else:
            raise

def account_name(string):
    c.account_name+=1
    if c.account_name == 2:
        raise
    else:
        accountName = pattern_name.match(string)
        if (accountName) and (len(string)<251) and (len(accountName.group(0)) == len(string)):
            return string
        else:
            raise

def ip_address(string):
    c.ip_address+=1
    if c.ip_address == 2:
        raise
    else:
        ipAddress = pattern_ip.match(string)
        if ((ipAddress) and (len(string) == len(ipAddress.group(0)))):
            return string
        else:
            raise

def port_number(string):
    c.port_number+=1
    if c.port_number == 2:
        raise
    else:
        portNumber = pattern_number.match(string)
        if ((portNumber) and (len(string) == len(portNumber.group(0))) and (int(portNumber.group(0))>1023) and (int(portNumber.group(0))<65536)):
            return int(portNumber.group(0))
        else:
            raise

def account_balance(string):
    c.account_balance+=1
    if (c.flagInputComb == 1) or (c.account_balance == 2):
        raise
    else:
        c.flagInputComb = 1
        accountBalance = pattern_float.match(string)
        if (accountBalance):
            string = string.replace('.','')
            if ((long(string)>=1000L) and (long(string)<=429496729599L)):
                return long(string)
            else:
                raise
        else:
            raise

def deposit_amount(string):
    c.deposit_amount+=1
    if (c.flagInputComb == 1) or (c.deposit_amount == 2):
        raise
    else:
        c.flagInputComb = 1
        depositAmount = pattern_float.match(string)
        if (depositAmount):
            string = string.replace('.','')
            if ((long(string)>0L) and (long(string)<=429496729599L)):
                return long(string)
            else:
                raise
        else:
            raise

def withdraw_amount(string):
    c.withdraw_amount+=1
    if (c.flagInputComb == 1) or (c.withdraw_amount == 2):
        raise
    else:
        c.flagInputComb = 1
        withdrawAmount = pattern_float.match(string)
        if (withdrawAmount):
            string = string.replace('.','')
            if ((long(string)>0L) and (long(string)<=429496729599L)):
                return long(string)
            else:
                raise
        else:
            raise

##
 #atm<-->bank protocol
##
def read_card_file(authCardFile):
    # Create the cardFile if not exist
    if (os.path.isfile(authCardFile) == False):
        with open(authCardFile, "w") as file:
            token = os.urandom(32)
            file.write(token)
    # Reading the card-file and send back the content
    with open(authCardFile, "r") as file:
        token = file.read(32)
    return token

# Method to read the bank.auth file
def read_auth_file(bankAuthFile):
    with open(bankAuthFile, "r") as file:
         token=file.read(32)
    return token

#TODO: Use key from auth file
def authenticate(client, bankAuthFile):
    global g_cryptokey
    r2 = os.urandom(32)
    client.sendall(r2)
    r1 = client.recv(1024)
    bankAuthContent = read_auth_file(bankAuthFile)
    challenge=hmac.new(bankAuthContent, r1+r2, hashlib.sha256).hexdigest()
    # PBKDF2 can be used here instead of this:
    #g_cryptokey=hmac.new(bankAuthContent, r2+r1+"1", hashlib.sha256).digest()
    client.sendall(challenge)
    response = client.recv(1024)
    if not (hmac.compare_digest(hmac.new(bankAuthContent, r2+r1, hashlib.sha256).hexdigest(), response)):
        raise Exception
    return

'''
# Method to read the bank.auth file
def read_logtime_file(logTimefile):
    with open(logTimefile, "r") as file:
         token=file.readline()
    return float(token)

# Method to read the bank.auth file
def addtime_logtime_file(logTimefile, timeToAdd):
    #pass
    logTimefile = "/home/bibi/working_repo/test/testTime/" + logTimefile
    currentTime = read_logtime_file(logTimefile)
    with open(logTimefile, "w") as file:
        file.write(str(currentTime+timeToAdd) + '\n')
        file.flush()
'''

def send_command_to_server(command, args):
    global g_cryptokey
    #starttime = time.time()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.settimeout(10)
    try:
        # connect to our target host
        server.connect((args.ipAddress,args.portNumber))
        #addtime_logtime_file('closesocket.time', (time.time() - starttime))
        #starttime = time.time()
        authenticate(server, args.authFile)
        #addtime_logtime_file('auth.time', (time.time() - starttime))
        #starttime = time.time()
        #f = Fernet(base64.urlsafe_b64encode(g_cryptokey))
        #buff = f.encrypt(command)
        #addtime_logtime_file('cypher.time', (time.time() - starttime))
        #starttime = time.time()
        server.sendall(command)
        buff = server.recv(4096)
        #addtime_logtime_file('exec_cmd.time', (time.time() - starttime))
        #starttime = time.time()
        #data = f.decrypt(buff,20)
        #addtime_logtime_file('cypher.time', (time.time() - starttime))
        #starttime = time.time()
        server_response = pickle.loads(buff)
        if (server_response.status == "ERROR"):
            sys.exit(255)
        parse_response(server_response)
        #addtime_logtime_file('parseresponse.time', (time.time() - starttime))
    except Exception as e:
        #print '-'*60
        #traceback.print_exc(file=sys.stdout)
        #print '-'*60
        sys.exit(63)

    finally:
        #starttime = time.time()
        l_onoff = 1
        l_linger = 0
        server.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger))
        server.close()
        #addtime_logtime_file('closesocket.time', (time.time() - starttime))

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



def parse_response(transaction):
    if (transaction.status == "OK"):
        if (transaction.op == "NEW"):
            print('{\"initial_balance\": %s, \"account\": \"%s\"}' % (process_amount_to_string(transaction.amount), transaction.account))
        elif (transaction.op == "GET"):
            print('{\"account\": \"%s\", \"balance\": %s}' % (transaction.account, process_amount_to_string(transaction.amount)))
        elif (transaction.op == "WIT"):
            print('{\"account\": \"%s\", \"withdraw\": %s}' % (transaction.account, process_amount_to_string(transaction.amount)))
        elif (transaction.op == "DEP"):
            print('{\"account\": \"%s\", \"deposit\": %s}' % (transaction.account, process_amount_to_string(transaction.amount)))

class AtmTransaction:
    def __init__(self, op="", account="", pin="", amount=0L, status=""):
        self.op = op
        self.account = account
        self.pin = pin
        self.amount = amount
        self.status = status

if (__name__ == "__main__"):
    try:
        ##
         #Argument Parser Setup
        ##
        parser = argparse.ArgumentParser(usage=False, add_help=False)

        #[-s <auth-file>] DEFAULT:bank.auth
        parser.add_argument('-s', dest='authFile', default='bank.auth', type=file_auth)
        #[-c <card-file>] DEFAULT:<account-name>.card
        parser.add_argument('-c', dest='cardFile', type=file_card)
        #-a <account> E.G: -a bob
        parser.add_argument('-a', dest='accountName', type=account_name, required=True)
        #[-i <ip-address>] DEFAULT:127.0.0.1
        parser.add_argument('-i', dest='ipAddress', default='127.0.0.1', type=ip_address)
        #[-p <port>] DEFAULT:3000
        parser.add_argument('-p', dest='portNumber', default='3000', type=port_number)
        #-g
        parser.add_argument('-g', action='count')
        #-n <balance>
        parser.add_argument('-n', dest='accountBalance', type=account_balance)
        #-d <amount>
        parser.add_argument('-d', dest='depositAmount', type=deposit_amount)
        #-w <amount>
        parser.add_argument('-w', dest='withdrawAmount', type=withdraw_amount)

        args = parser.parse_args()
        if ( ((c.flagInputComb == 0) and (not(args.g))) or ((c.flagInputComb == 1) and (args.g)) or ((c.flagInputComb == 0) and (args.g) and (args.g > 1)) ):
            raise Exception

    except Exception as e:
        # Error occured, exit with error code 255
        sys.exit(255)


    if(not args.cardFile):
        args.cardFile = args.accountName + '.card'

    #####################################################################################################
    #print "At the end we have arguments:\n", args

    '''
    atm [-s <auth-file>] [-i <ip-address>] [-p <port>] [-c <card-file>] -a <account> -n <balance>
    atm [-s <auth-file>] [-i <ip-address>] [-p <port>] [-c <card-file>] -a <account> -d <amount>
    atm [-s <auth-file>] [-i <ip-address>] [-p <port>] [-c <card-file>] -a <account> -w <amount>
    atm [-s <auth-file>] [-i <ip-address>] [-p <port>] [-c <card-file>] -a <account> -g
    '''
    #-s <auth-file>==args.authFile=<auth-file>----->Always exist, string, default=bank.auth
    #-c <card-file>==args.cardFile=<card-file>----->Always exist, string, default=account_name.card
    #-a <account>==args.accountName=<account>------>Always exist, string
    #-i <ip-address>==args.ipAddress=<ip-address>-->Always exist, string, default=127.0.0.1
    #-p <port>==args.portNumber=<port>------------->Always exist, long, default=3000
    #-g ==args.g----------------------------------->Optional
    #-n <balance>==args.accountBalance=<balance>--->Optional, long
    #-d <amount>==args.depositAmount=<amount>------>Optional, long
    #-w <amount>==args.withdrawAmount=<amount>------>Optional, long
    #######################################################################################################

    # Read or create the card-file
    try:
        cardFileContent = read_card_file(args.cardFile)
    except:
        sys.exit(255)


    if (args.g):
        atmPacket = AtmTransaction(op="GET")
    elif (args.depositAmount > 0):
        atmPacket = AtmTransaction(op="DEP", amount=args.depositAmount)
    elif (args.accountBalance > 0):
        atmPacket = AtmTransaction(op="NEW", amount=args.accountBalance)
    elif (args.withdrawAmount > 0):
        atmPacket = AtmTransaction(op="WIT", amount= args.withdrawAmount)

    atmPacket.account = args.accountName
    atmPacket.pin = cardFileContent
    #authFile
    # Sending command

    send_command_to_server(pickle.dumps(atmPacket), args)
    #All ok
    sys.exit(0)
