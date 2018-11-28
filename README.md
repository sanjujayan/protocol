# protocol


Packet implementation

# some imports
import socket, sys
from struct import *

f =open("display.txt","r")


# checksum functions needed for calculation checksum
def checksum(msg):
    s = 0


    # loop taking 2 characters at a time
    #print msg
    #print len(msg)
    if len(msg)%2 == 1:
      msg = msg+' '

      for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        s = s + w

    s = (s>>16) + (s & 0xffff);
    s = s + (s >> 16);

    #complement and mask to 4 byte short
    s = ~s & 0xffff

    return s

#create a raw socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

# tell kernel not to put in headers, since we are providing it, when using IPPROTO_RAW this is not necessary
# s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# now start constructing the packet
packet = '';

source_ip = '192.168.3.241'
dest_ip ='127.0.0.1' # or socket.gethostbyname('www.google.com')

# ip header fields
op_hlen = 4
#op_ver = 4
#op_tot_len = 0  # kernel will fill the correct total length
op_id = 54321   #Id of this packet
#op_frag_off = 0
op_ttl = 255
op_proto = socket.IPPROTO_TCP
op_check = 0    # kernel will fill the correct checksum
op_saddr = socket.inet_aton ( source_ip )   #Spoof the source ip address if you want to
op_daddr = socket.inet_aton ( dest_ip )

#op_ihl_ver = (ip_ver << 4) + op_hlen

# the ! in the pack format string means network order
op_header = pack('!B4s4sHHHB',op_hlen,op_daddr,op_saddr,op_check,op_id,op_ttl,op_proto)





# tcp header fields
tcp_source = 1234   # source port
tcp_dest = 4321   # destination port
tcp_seq = 454
tcp_ack_seq = 0
tcp_doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
#tcp flags
tcp_fin = 0
tcp_syn = 1
tcp_rst = 0
tcp_psh = 0
tcp_ack = 0
tcp_urg = 0
tcp_window = socket.htons (5840)    #   maximum allowed window size
tcp_check = 0
tcp_urg_ptr = 0

tcp_offset_res = (tcp_doff << 4) + 0
tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)

# the ! in the pack format string means network order
tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)

user_data = f.read()
print user_data

# pseudo header fields
source_address = socket.inet_aton( source_ip )
dest_address = socket.inet_aton(dest_ip)
placeholder = 0
protocol = socket.IPPROTO_TCP
tcp_length = len(tcp_header) + len(user_data)

psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
psh = psh + tcp_header + user_data;

tcp_check = checksum(psh)
#print tcp_checksum

# make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
tcp_header = pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)

# final full packet - syn packets dont have any data
packet = op_header + tcp_header + user_data

#Send the packet finally - the port specified has no effect
b = s.sendto(packet, (dest_ip , 0 ))    # put this in a loop if you want to flood the target
print b,"bytes send"


User Interfaces

Sending Interface

from tkinter import *
import os,sys

#def onclick(B):
#   pass


root=Tk()
def retrieve_input():
    f = open("display.txt","w")
    sys.stdout = f
    inputValue=textBox.get("1.0","end-1c")
    print(inputValue)
    f.close()
    os.system('python packet.py')

L1 = Label(root, text="ENTER HERE")
L1.pack(side = TOP)
textBox=Text(root, height=2, width=10)
textBox.pack()
buttonCommit=Button(root, height=1, width=10, text="send", bg = "red",
                    command=lambda: retrieve_input())

buttonCommit.pack()

#print("text: %s\n",(E1.get())
#input = E1.get()
#print(input)

root.mainloop()


Receiving Interface
 
from tkinter import *
import os,sys
import re
 
f = open('capture.txt', 'r') # open file in read mode
#data = f.read()      # copy to a string
#if data == "0$_1":             
 #  print (data)  
#f.close()  
 
root=Tk()
 
for line in f:
  for part in line.split(","):
    if "0$_1" in part:
      i = line.index("0$_1")
      L1 = Label(root, text= part[i+4:]) 
      L1.pack(side = TOP)
f.close()   
#buttonCommit=Button(root, height=1, width=10, text="send", bg = "red")
 
#buttonCommit.pack()
 
#print("text: %s\n",(E1.get())
#input = E1.get()
#print(input)
 
root.mainloop()




Packet Sniffing

#Packet sniffer in python
#For Linux - Sniffs all incoming and outgoing packets :)
#Silver Moon (m00n.silv3r@gmail.com)

import socket, sys
from struct import *

f = open("capture.txt","w")
sys.stdout = f


#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b

#create a AF_PACKET type raw socket (thats basically packet level)
#define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */



try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

# receive a packet
while True:
    packet = s.recvfrom(65565)
    print packet,"   "
    #packet string from tuple
    packet = packet[0]

    #parse ethernet header
    eth_length = 14

    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])

    #if eth_addr(packet[6:12]) !="a0:d3:7a:75:9e:a0 ": 
     #    print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)


    if eth_protocol == 146:
      op_header = packet[eth_length:16+eth_length]
       #now unpack them :)
      oph = unpack('!B4s4sHHHB' , ip_header)

      ophlen = oph[0]
      #version_ihl = iph[0]
      #version = version_ihl >> 4
      #ihl = version_ihl & 0xF

      #iph_length = ihl * 4
      op_id = iph[3] 
      opttl = iph[5]
      protocol = iph[4]
      d_addr = socket.inet_ntoa(iph[1]);
      s_addr = socket.inet_ntoa(iph[2]);

      print  ' OP Header Length : ' + str(ophlen) + ' TTL : ' + str(opttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
    #Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8 :
        #Parse IP header
        #take first 20 characters for the ip header
        ip_header = packet[eth_length:20+eth_length]

        #now unpack them :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);

        if d_addr =="192.168.0.16" :
    print 'Version : ,' + str(version) + ', IP Header Length : ,' + str(ihl) + ', TTL : ,' + str(ttl) + ', Protocol : ,' + str(protocol) + ',             Source Address : ,' + str(s_addr) + ', Destination Address : ,' + str(d_addr)

        #TCP protocol
        if protocol == 6:# and d_addr =="192.168.0.16" :
            t = iph_length + eth_length
            tcp_header = packet[t:t+20]

            #now unpack them :)
            tcph = unpack('!HHLLBBHHH' , tcp_header)

         
  source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4

            print ',Source Port : ,' + str(source_port) + ', Dest Port : ,' + str(dest_port) + ', Sequence Number : ,' + str(sequence) + ', Acknowledgement : ,' + str(acknowledgement) + ', TCP header length : ,' + str(tcph_length)

            h_size = eth_length + iph_length + tcph_length * 4
            data_size = len(packet) - h_size

            #get data from the packet
            data = packet[h_size:]

            #print 'Data : ' + data

        #ICMP Packets
        elif protocol == 1 and d_addr =="192.168.0.16":
            u = iph_length + eth_length
            icmph_length = 4
            icmp_header = packet[u:u+4]

            #now unpack them :)
            icmph = unpack('!BBH' , icmp_header)

            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]

         




   print ',Type : ,' + str(icmp_type) + ', Code : ,' + str(code) + ', Checksum : ,' + str(checksum)

            h_size = eth_length + iph_length + icmph_length
            data_size = len(packet) - h_size

            #get data from the packet
            data = packet[h_size:]

            #print 'Data : ' + data

        #UDP packets
        elif protocol == 17 and d_addr =="192.168.0.16" :
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u+8]

            #now unpack them :)
            udph = unpack('!HHHH' , udp_header)

           
source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]

            print ', Source Port : ,' + str(source_port) + ', Dest Port : ,' + str(dest_port) + ', Length : ,' + str(length) + ', Checksum : ,' + str(checksum)


            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size

            #get data from the packet
            data = packet[h_size:]

         #   print 'Data : ' + data

        #some other IP packet like IGMP
        else :
            print ',145'

        print

