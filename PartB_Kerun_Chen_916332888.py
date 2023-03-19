import socket
import sys
import os
import time

port = 53
host = sys.argv[1]
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

rootDNS = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4', 
'198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']

def buildFlags():
    QR = '0'
    Qpcode = '0000'
    AA = '0'
    TC = '0'
    RD = '1'
    RA = '0'
    Z = '000'
    Rcode = '0000'
    return int(QR+Qpcode+AA+TC+RD+RA+Z+Rcode, 2).to_bytes(2, 'big')

def buildheader():
    #ID is always the first two bytes in the header msg
    ID = os.urandom(2)

    #Flags
    Flags = buildFlags()

    #QDCOUNT
    QDCOUNT = b'\x00\x01'

    #ANCOUNT
    ANCOUNT = b'\x00\x00'

    #NSCOUNT
    NSCOUNT = b'\x00\x00'

    #ARCOUNT
    ARCOUNT = b'\x00\x00'

    return ID+Flags+QDCOUNT+ANCOUNT+NSCOUNT+ARCOUNT

def buildQuestion():
    domain = ''
    TLD = ''
    beforedot = 1
    for char in host:
        if char == '.':
            beforedot = 0
            continue
        if beforedot:
            domain += char
        else:
            TLD += char
        
    #QNAME
    QNAME = (len(domain)).to_bytes(1, 'big') + bytes(domain.encode()) + (len(TLD)).to_bytes(1, 'big') + bytes(TLD.encode()) + b'\x00'

    #QTYPE
    QTYPE = b'\x00\x01'

    #QCLASS
    QCLASS = b'\x00\x01'

    return QNAME + QTYPE + QCLASS

def buildQuery():
    return buildheader() + buildQuestion()

query = buildQuery()

def getIp(msg):
    ip = ''
    #Since the IPv4 addr length is always 4
    #As long as you find the last '\x00\x04', 
    #you can determine that the following 4 bytes' data is the ipv4 address
    index = msg.rfind(b'\x00\x04')

    ipinfo = msg[index+2: index+6]
    for byte in ipinfo:
        ip += repr(byte) + '.'
    
    return ip[:-1]


def sendandrecv(ip):
    server.sendto(query, (ip, port))
    msg, addr = server.recvfrom(512)
    return msg

def DNSServer():
    start = time.time()
    rootMsg = ''
    for ip in rootDNS:
        rootIp = ip
        start = time.time()
        rootMsg = sendandrecv(ip)
        end = time.time()
        #Set the timer to 2s
        if end- start < 2:
            break
    TLDip = getIp(rootMsg)
    TLDMsg = sendandrecv(TLDip)
    Authip = getIp(TLDMsg)
    AuthMsg = sendandrecv(Authip)
    HTTPip = getIp(AuthMsg)
    end = time.time()
    print('Domain: ' + host)
    print('Root server IP address: ' + rootIp)
    print('TLD server IP address: ' + TLDip)
    print('Authoritative server IP address: ' + Authip)
    print('HTTP Server IP address: ' + HTTPip)
    return(repr(end - start))

DNSServer()




#Below code are used for calculating RTT..
#Since the expected output only conatins ip addrs, I commented them out. 
'''
def getRTT(dstip):
    start = time.time()
    sendandrecv(dstip)
    end = time.time()
    return repr(start - end)

print('Root RTT: ' + getRTT('198.41.0.4')) 
output: Root RTT: -0.022912263870239258

print('TLD RTT: ' + getRTT('192.55.83.30')) 
output: TLD RTT: -0.09204626083374023

print('Auth RTT: ' + getRTT('205.251.193.129')) 
output: Auth RTT: -0.03162574768066406

resolvetime = DNSServer()
print('Resolve time: ' + repr(resolvetime))
'''


    



