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
        # self.status = 1
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
        TAB_2 + 'Data: ' + str(self.data) + "\n"

    def addUnsupportedEthernetProtocol(self, data):
        self.status = -1
        self.data = data

    def printUnsupportedEthernetProtocol(self):
        return "Unsupported Ethernet Protocol: \n" + "(only IPv4(8) Accepted) \n" + TAB_2 + "Protocol Number: " + str(self.eth_proto) + "\n"  + \
        TAB_2 + "Data: " + str(self.data) + "\n"

    def getRepresentation(self):
        try:
            #                                        self.proto
            return '{} \t\t {} \t\t {}'.format(self.switchToText(self.status), self.src, self.target)
        except:
            #                                self.eth_proto
            return '{} \t\t {} \t\t {}'.format("IPv4", self.src_mac ,self.dest_mac)

    def switchToText(self, num):
        if num == 2:
            return "ICMP"
        elif num == 3:
            return "TCP"
        elif num == 4:
            return "UDP"

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
