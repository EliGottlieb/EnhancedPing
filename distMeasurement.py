import socket
import struct
from threading import Thread
import time

def getPort():#This method will return a random open port for probing packets. Before returning the port, the method will add the random open port to an array to be matched later
    tcp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tcp.bind(('', 0))
    addr, port = tcp.getsockname()
    tcp.close()
    ports.append(port)
    return port

def parseTargets():#This method reads the targets.txt file and returns an array of both hostnames and ips for sending and later matching
    f = open('targets.txt')
    targetIPs = []
    targetHostnames = []
    for line in f:
        targetHostnames.append(line.rstrip())
        targetIPs.append(socket.gethostbyname(line.rstrip()))
    f.close()
    return targetHostnames,targetIPs
   
def createIPHeader(sourceIP, destIP, time): #This method creates an IP header for a probing packet. This method uses source IP, distnation IP, and an adapted version of a timestamp
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0  
    ip_id = time #this is an adapted timestamp. It may be the same as other IPID's sent, but this is fine as there are two other matching criteria
    IPIDs.append(time) #this IPID is added to a list that will used to be matched with later
    ip_frag_off = 0
    ip_ttl = datagramTTL
    ip_proto = socket.IPPROTO_UDP
    ip_check = 0   
    ip_saddr = socket.inet_aton (sourceIP)
    ip_daddr = socket.inet_aton (destIP)
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    return struct.pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

def send(startTime):#this method will be run in its own thread. This method will create ip and udp headers for each packet, add each to the payload, and send the probing packets
    targetHostnames, targetIPs = parseTargets() #the list of hostnames and ips are saved with parseTargets()
    msg = "Measurement for class project. Questions to Student esg58@case.edu or Professor mxr136@case.edu"
    payload = bytes(msg + 'a'*(1472 - len(msg)),'ascii') #creation of the payload of the packet
    send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,socket.IPPROTO_RAW) #creation of a raw socket which will send probing packets
    for i in range(len(targetIPs)): #this for loop will iterate through the ips and create each header for each probing packet and send them
        destIP = targetIPs[i]
        hostname = targetHostnames[i]
        print("Testing %s" % hostname)
        try:
                ipHeader = createIPHeader(sourceIP, destIP, convertTime(startTime))#creation of the ip header
                print(ipHeader)
                udpHeader = struct.pack('!HHHH', getPort(), 33434, len(payload)+8, 0)#creation of the udp header
                probe_packet = ipHeader + udpHeader + payload#putting ip header and udp header and payload together to make a udp packet
                sendTimes.append(time.time())
                send_socket.sendto(probe_packet, (destIP, port))
        except socket.error:
                print("uh oh")
        print(30*"-")
    send_socket.close()

def receive(startTime):#this method will be run in its own thread. This method will receive and process each received ICMP packet and match it using three arrays containing the three criteria
    recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)#creaiton of a raw socket which will receive ICMP packets
    recv_socket.bind(("", 0))
    targetHostnames, targetIPs = parseTargets()#the list of hostnames and ips are saved with parseTargets()
    for i in range(len(targetHostnames)):#gives the receive socket 10 maximum cycles to receive different packets
        recv_socket.settimeout(5)
        try:
            recPacket = recv_socket.recv(1500)
            recTime = time.time()
            returned_ttl = recPacket[36]
            hop_count = datagramTTL - returned_ttl
            rp_sourceIP = socket.inet_ntoa(recPacket[12:16])
            rp_IPID = recPacket[32:34]
            rp_SrcPort = recPacket[48:50]
            j = 0
            while j < len(targetIPs):#loop goes through information in each matching criteria and attempts to find a match. When a match is found, the corresponding information of that match is removed from the arrays
                sp_destIP = targetIPs[j]           
                sp_IPID = struct.pack('!H', IPIDs[j])#puts IPID from array into a form comparable to the IPID being pulled straight from the ICMP packet
                sp_SrcPort = struct.pack('!H', ports[j])
                match = ""#a string to build and save the different matches that could be possible between probing packet information and ICMP packet information
                if(rp_sourceIP == sp_destIP or rp_SrcPort == sp_SrcPort):
                    if(rp_sourceIP == sp_destIP):
                        match="Addr"
                    if(rp_IPID == sp_IPID):
                        if(len(match)>0):
                            match=match+ ", "
                        match=match+"IPID"
                    if(rp_SrcPort == sp_SrcPort):
                        if(len(match)>0):
                            match=match+ ", "
                        match=match+"Port"
                    print("Target:", targetHostnames[j], ":", targetIPs[j], "; Hops:", hop_count, "; RTT:", round(recTime-sendTimes[j],3)*1000  , "ms; Matched on:{", match, "} Payload length:", len(recPacket)-56,'\n')
                    targetHostnames.remove(targetHostnames[j])#removes corresponding information after match is found so as to not duplicate matches and save searching time
                    targetIPs.remove(targetIPs[j])
                    IPIDs.remove(IPIDs[j])
                    ports.remove(ports[j])
                    break
                j+=1
        except socket.timeout:
            print( "-- Timed Out --")
            for p in range(len(targetHostnames)):
                print(targetHostnames[p])# a list of hostnames that did not get matched with a response
            break
    recv_socket.close()    

def convertTime(startTime):#This method will convert a given time into a form that will be viable for the IPID field in an ip header
    elapsed = time.time()-startTime
    delta_ms = round(elapsed,3)
    return int(delta_ms*1000)

datagramTTL = 32
port = 33434
sourceIP = socket.gethostbyname(socket.gethostname())
#sourceIP = "172.28.45.209"
#sourceIP = "172.26.195.127"
#Arrays that contain information from the probing packets to be compared to information from the ICMP responses 
IPIDs = []
ports = []
sendTimes = []

def main():
    startTime = time.time()
    x = Thread(target=send,args=(startTime,))#this thread will independently send probing packets
    y = Thread(target=receive, args=(startTime,))#this thread will independently receive ICMP packets
    x.start()
    y.start()

if __name__=="__main__":
    main()
