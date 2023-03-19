import socket
import sys
import os
import time


host = sys.argv[1]
DNSPort = 53
HTTPPort = 80
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#IP of DNS resovlers
Iran = ['91.245.229.1', '46.224.1.42', '185.161.112.34'] 
USA = ['169.237.229.88', '168.62.214.68', '104.42.159.98']
Canada = ['136.159.85.15', '184.94.80.170', '142.103.1.1']
ResovlerLst = [Iran, USA, Canada]

#Flags format
'''+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+'''

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


#Header section format
''' +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+'''

def buildheader():
    #ID
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

#Question section format
''' +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+'''

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

def getDNSResponse(DNSResolver):
    msg = ''
    for ip in DNSResolver:
        #Start a timer
        starttime = time.time()

        #Send DNS request and recieve form the resolver
        udp_socket.sendto(query, (ip, DNSPort))
        msg, addr = udp_socket.recvfrom(512)

        #End the timer
        endtime = time.time()
        diff = endtime- starttime

        #Check if more than 10s
        if(diff < 10): break
    return msg

def getIp(msg):
    ip = ''
    #Ipv4 ip address always occupy the last 4 bytes
    ipinfo = msg[-4:]

    #Turn bytes to human readble
    for byte in ipinfo:
        ip += repr(byte) + '.'
    
    #remove the last '.' 
    return ip[:-1]

#-------------------------------------------------------------------
#Get HTTP response:     
#Since there is sometimes an error when establish a tcp connection. 
#In order to ensure the normal operation of the program, I only show 
#the implementation but not call it. But below shows how I get the 
#html file of tmz.com
#-------------------------------------------------------------------
def getHTTPResponse(ip):
    tcp_socket.connect((ip, HTTPPort))
    start = time.time()
    #https://www.geeks3d.com/hacklab/20190110/python-3-simple-http-request-with-the-socket-module/
    request = "GET / HTTP/1.1\r\nHost:%s\r\n\r\n" % ip
    tcp_socket.send(request.encode())  
    response = tcp_socket.recv(4096)
    end = time.time()
    diff = end- start

    #Get the RTT between HTTP client to server
    print(diff) 
    return response

def DNSClient():
    ipLst = []
    for DNSResovler in ResovlerLst:
        msg = getDNSResponse(DNSResovler)
        ip = getIp(msg)
        ipLst.append(ip)
    print('Doamin: ' + host)
    print('HTTP Server IP address: ')
    for ip in ipLst:
        print(ip)
    
DNSClient()




