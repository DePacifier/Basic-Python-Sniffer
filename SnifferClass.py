import struct
import socket
import textwrap
import platform
from DataClass import FormattedData
import constants


class Sniffer():

    def __init__(self,protocolList, IP):
        self.protocolList = protocolList
        self.IP = IP
        self.status = 0
        self.operatingSystem = platform.system()

        if self.operatingSystem == "Linux":
            self.connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            self.protocols = constants.protocols["Linux"]

        elif self.operatingSystem == "Windows":
            self.HOST = socket.gethostbyname(socket.gethostname())
            self.connection = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            # Creating raw socket and binding it to the public interface
            self.connection.bind((self.HOST,0))
            # Include IP headers
            self.connection.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL,1)
            # Reciveing all packets
            self.connection.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            self.protocols = constants.protocols["Windows"]

        else:
            self.connection = None
            self.protocols = None

    def sniffOne(self):

        if self.connection == None or self.protocols == None:
            return None

        print("from sniff One protocols are :", self.protocolList)
        self.status = 1

        raw_data, addr = self.connection.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = self.unpack_ethernet_frame(raw_data)
        self.newDataHolder = FormattedData(dest_mac, src_mac, eth_proto)

        #printEtherenet
        if eth_proto == self.protocols["ipv4_protocol"]:
            version, header_length, ttl, proto, src, target, data = self.ipv4_packet(data)
            self.newDataHolder.addIPv4Data(version, header_length, ttl, proto, src, target)
            #printIPv4
            if self.IP != "" and self.IP != str(src) or self.IP != "" and self.IP != str(target):
                return None

            print("passed")
            # Check if ICMP
            if proto == self.protocols["icmp_protocol"] and constants.icmp in self.protocolList:
                icmp_type, code, checksum, data = self.icmp_packet(data)
                self.newDataHolder.addICMPData(icmp_type, code, checksum,data)
                # print(self.newDataHolder.getInformation())
                return self.newDataHolder
                #printICMP

            # Check if TCP
            elif proto == self.protocols["tcp_protocol"] and constants.tcp in self.protocolList:
                src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack,flag_psh, flag_rst, flag_syn, flag_fin, data = self.tcp_segment(data)
                self.newDataHolder.addTCPData(src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack,flag_psh, flag_rst, flag_syn, flag_fin, data)
                # print(self.newDataHolder.getInformation())
                return self.newDataHolder
                #printTCP

            # Check if UDP
            elif proto == self.protocols["udp_protocol"] and constants.udp in self.protocolList:
                src_port, dest_port, size, data = self.udp_segment(data)
                self.newDataHolder.addUDPData(src_port, dest_port, size)
                print(self.newDataHolder.getInformation())
                return self.newDataHolder
                #printUDP
                
            # Other Types
            # elif 0 in self.protocolList:
            #     self.newDataHolder.addUnsupportedProtocol(proto, data)
            #     print(self.newDataHolder.printUnsupportedProtocol())
            #     return self.newDataHolder
                #printUnsupportedproto
            else:
                self.newDataHolder.addUnsupportedProtocol(proto, data)
                print(self.newDataHolder.printUnsupportedProtocol())
                return None


        # elif 0 in self.protocolList:
        #     self.newDataHolder.addUnsupportedEthernetProtocol(data)
        #     print(self.newDataHolder.printUnsupportedEthernetProtocol())
        #     return self.newDataHolder
            #printUnsupportedetherentproto
        else:
            self.newDataHolder.addUnsupportedEthernetProtocol(data)
            # print(self.newDataHolder.printUnsupportedEthernetProtocol())
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
    myobj = Sniffer([0,1,6,17],"")
    
    while True:
        myobj.sniffOne()