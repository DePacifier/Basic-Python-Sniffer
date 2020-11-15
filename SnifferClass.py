import struct
import socket
import textwrap


TAB_1 = '  - '
TAB_2 = '    - '
TAB_3 = '      - '
TAB_4 = '        - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

class FormattedData():

    def __init__(self, dest_mac, src_mac, eth_proto):
        self.dest_mac = dest_mac
        self.src_mac = src_mac
        self.eth_proto = eth_proto

    def printEthernetProtocol(self):
        return '\n Ethernet Frame: \n' + TAB_1 + "Destination: {}, Source {}, Protocol: {}".format(self.dest_mac, self.src_mac, self.eth_proto) + "\n"

    def addIPv4Data(self,version, header_length, ttl, proto, src, target):
        self.status = 1
        self.version = version
        self.header_length = header_length
        self.ttl = ttl
        self.proto = proto
        self.src = src
        self.target = target

    def printIPv4Data(self):
        return TAB_1 + 'IPv4 Packet: ' + TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(self.version, self.header_length, self.ttl) + \
        TAB_2 + 'Protocol: {}, Source IP: {}, Destination IP: {}'.format(self.proto, self.src, self.target) + "\n"

    def addICMPData(self,icmp_type, code, checksum, data):
        self.status = 2
        self.icmp_type = icmp_type
        self.code = code
        self.checksum = checksum
        self.data = data

    def printICMPData(self):
        return TAB_1 + 'ICMP Packet: ' + TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(self.icmp_type, self.code, self.checksum) + \
        TAB_2 + 'Data: ' + self.format_multi_line(DATA_TAB_3, self.data) + "\n"

    def addTCPData(self,src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack,flag_psh, flag_rst, flag_syn, flag_fin, data):
        self.status = 3
        self.src_port = src_port
        self.dest_port = dest_port
        self.sequence = sequence
        self.acknowledgement = acknowledgement
        self.flag_urg = flag_urg
        self.flag_ack = flag_ack
        self.flag_psh = flag_psh
        self.flag_rst = flag_rst
        self.flag_syn = flag_syn
        self.flag_fin = flag_fin
        self.data = data

    def printTCPData(self):
        return TAB_1 + 'TCP Segment: ' + TAB_2 + 'Source Port: {}, Destination Port: {}, Sequence: {}, Acknowledgment: {}'.format(self.src_port, self.dest_port, self.sequence, self.acknowledgement) + \
        TAB_2 + 'Flags: ' + TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(self.flag_urg, self.flag_ack, self.flag_psh) + TAB_3 + 'RSH: {}, SYN: {}, FIN: {}'.format(self.flag_rst, self.flag_syn, self.flag_fin) + \
        TAB_2 + 'Data: ' + self.format_multi_line(DATA_TAB_3, self.data) + "\n"

    def addUDPData(self,src_port, dest_port, size):
        self.status = 4
        self.src_port = src_port
        self.dest_port = dest_port
        self.size = size

    def printUDPData(self):
        return TAB_1 + 'UDP Segment: ' + TAB_2 + 'Source Port: {}, Destination Port: {}, Size: {}'.format(self.src_port, self.dest_port, self.size) + "\n"

    def addUnsupportedProtocol(self,proto, data):
        self.status = 0
        self.proto = proto
        self.data = data

    def printUnsupportedProtocol(self):
        return TAB_1 + "Unsupported Protocol: \n" + '\t   '+ "(only ICMP(1) TCP(6) UDP(17) Accepted)" + TAB_2 + "Protocol Number: " + str(self.proto) + \
        TAB_2 + 'Data: ' + self.format_multi_line(DATA_TAB_3, self.data) + "\n"

    def addUnsupportedEthernetProtocol(self, data):
        self.status = -1
        self.data = data

    def printUnsupportedEthernetProtocol(self):
        return "Unsupported Ethernet Protocol: \n" + "(only IPv4(8) Accepted) \n" + TAB_2 + "Protocol Number: " + str(self.eth_proto) + "\n"  + \
        TAB_2 + "Data: " + self.format_multi_line(DATA_TAB_3, self.data) + "\n"

    def getRepresentation(self):
        try:
            return '{} \t\t {} \t\t {}'.format(self.proto, self.src, self.target)
        except:
            return '{} \t\t {} \t\t {}'.format(self.eth_proto, self.src_mac ,self.dest_mac)

    def getInformation(self):
        returnStr = self.printEthernetProtocol()
        if self.status == -1:
            returnStr += self.printUnsupportedEthernetProtocol()

        if self.status == 0:
            returnStr += self.printUnsupportedProtocol()

        if self.status > 0:
            returnStr += self.printIPv4Data()

        if self.status == 2:
            returnStr += self.printICMPData()

        if self.status == 3:
            returnStr += self.printTCPData()

        if self.status == 4:
            returnStr += self.printUDPData()

        return returnStr


    def format_multi_line(self,prefix, string, size=80):
        size -= len(prefix)
        if isinstance(string, bytes):
            string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
            if size % 2:
                size -= 1
        
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])



    

class Sniffer():

    def __init__(self,protocolList, IP):
        self.protocolList = protocolList
        self.IP = IP
        self.status = 0


    def sniffOne(self):

        print("from sniff One protocols are :", self.protocolList)
        self.status = 1
        self.connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

        # self.HOST = socket.gethostbyname(socket.gethostname())
        # self.connection = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        # # Creating raw socket and binding it to the public interface
        # self.connection.bind((self.HOST,0))
        # # Include IP headers
        # self.connection.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL,1)
        # # Reciveing all packets
        # self.connection.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        raw_data, addr = self.connection.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = self.unpack_ethernet_frame(raw_data)
        self.newDataHolder = FormattedData(dest_mac, src_mac, eth_proto)

        #printEtherenet
        #check if protocol is IPv4 by 8 apparently its 524288,2831155200
        if eth_proto == 524288:
            version, header_length, ttl, proto, src, target, data = self.ipv4_packet(data)
            self.newDataHolder.addIPv4Data(version, header_length, ttl, proto, src, target)
            #printIPv4
            if self.IP != "" and self.IP != str(src) or self.IP != "" and self.IP != str(target):
                return None

            print("passed")
            # Check if ICMP
            if proto == 1 and 1 in self.protocolList:
                icmp_type, code, checksum, data = self.icmp_packet(data)
                self.newDataHolder.addICMPData(icmp_type, code, checksum,data)
                return self.newDataHolder
                #printICMP

            # Check if TCP
            elif proto == 6 and 6 in self.protocolList:
                src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack,flag_psh, flag_rst, flag_syn, flag_fin, data = self.tcp_segment(data)
                self.newDataHolder.addTCPData(src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack,flag_psh, flag_rst, flag_syn, flag_fin, data)
                return self.newDataHolder
                #printTCP

            # Check if UDP
            elif proto == 17 and 17 in self.protocolList:
                src_port, dest_port, size, data = self.udp_segment(data)
                self.newDataHolder.addUDPData(src_port, dest_port, size)
                return self.newDataHolder
                #printUDP
                
            # Other Types
            # elif 0 in self.protocolList:
            #     self.newDataHolder.addUnsupportedProtocol(proto, data)
            #     return self.newDataHolder
                #printUnsupportedproto
            else:
                return None


            # elif 0 in self.protocolList:
            #     self.newDataHolder.addUnsupportedEthernetProtocol(data)
            #     return self.newDataHolder
                #printUnsupportedetherentproto
        else:
            return None

            
            # print(self.newDataHolder.getInfromation())
            # return self.newDataHolder  
            

    def unpack_ethernet_frame(self,data):
        dest_mac, src_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
        return self.get_mac_addr(dest_mac), self.get_mac_addr(src_mac), socket.htonl(protocol), data[14:]

    # return properly formatted MAC address  
    def get_mac_addr(self,bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()

    # unpacks ipv4 packet 
    def ipv4_packet(self,data):
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        return version, header_length, ttl, proto, self.ipv4(src), self.ipv4(target), data[header_length:]

    def ipv4(self,addr):
        return '.'.join(map(str,addr))

    # ICMP
    def icmp_packet(self,data):
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        return icmp_type, code, checksum, data[4:]

    # TCP
    def tcp_segment(self,data):
        (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H',data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1
        return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack,flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

    # UDP
    def udp_segment(self,data):
        src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
        return src_port, dest_port, size, data[8:]


    def stopSniffing(self):
        print("sniffing class called and changed stop value")
        self.status = 0
        
    def addString(self,str1, str2):
        str1 = str1 + str2
        return str1



if __name__ == "__main__":
    myobj = Sniffer([0,1,6,17],"192.168.112.128")
    
    while True:
        myobj.sniffOne()