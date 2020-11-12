import struct
import socket
import textwrap

# HOST = socket.gethostbyname(socket.gethostname())
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '



def sniff():
    # Linux Version
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    # Win version
    # connection = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    # Creating raw socket and binding it to the public interface
    # connection.bind(("192.168.1.120",0))
    # Include IP headers
    # connection.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL,1)
    # Reciveing all packets
    # connection.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    while True:
        raw_data, addr = connection.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = unpack_ethernet_frame(raw_data)
        print('\n Ethernet Frame:')
        print(TAB_1 + "Destination: {}, Source {}, Protocol: {}".format(dest_mac, src_mac, eth_proto))
        print()

        #check if protocol is IPv4 by 8 apparently its 524288
        if eth_proto == 524288:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            print(TAB_1 + 'IPv4 Packet: ')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol: {}, Source IP: {}, Destination IP: {}'.format(proto, src, target))
            print()

            # Check if ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet: ')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(TAB_2 + 'Data: ')
                print(format_multi_line(DATA_TAB_3, data))
                print()

            # Check if TCP
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack,flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                print(TAB_1 + 'TCP Segment: ')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Sequence: {}, Acknowledgment: {}'.format(src_port, dest_port, sequence, acknowledgement))
                print(TAB_2 + 'Flags: ')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(flag_urg, flag_ack, flag_psh))
                print(TAB_3 + 'RSH: {}, SYN: {}, FIN: {}'.format(flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data: ')
                print(format_multi_line(DATA_TAB_3, data))
                print()

            # Check if UDP
            elif proto == 17:
                src_port, dest_port, size, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment: ')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Size: {}'.format(src_port, dest_port, size))
                print()
                
            # Other Types
            else:
                print(TAB_1 + "Unsupported Protocol: \n" + '\t   '+ "(only ICMP(1) TCP(6) UDP(17) Accepted)")
                print(TAB_2 + "Protocol Number: " + str(proto))
                print(TAB_2 + 'Data: ')
                print(format_multi_line(DATA_TAB_3, data))
                print()

        else:
            print(TAB_1 + "Unsupported Ethernet Protocol: \n" + '\t   ' + "(only IPv4(8) Accepted) ")
            print(TAB_2 + "Protocol Number: " + str(eth_proto))
            print(TAB_2 + "Data: ")
            print(format_multi_line(DATA_TAB_3, data))
            print()

# ethernet frame
def unpack_ethernet_frame(data):
    dest_mac, src_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htonl(protocol), data[14:]

# return properly formatted MAC address  
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# unpacks ipv4 packet 
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str,addr))

# ICMP
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# TCP
def tcp_segment(data):
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
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


sniff()