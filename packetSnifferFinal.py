# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '.\PacketSniffer.ui'
#
# Created by: PyQt5 UI code generator 5.15.1
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.

import SnifferClass
import threading
import textwrap
from PyQt5 import QtCore, QtGui, QtWidgets


DATA_TAB = "\t\t\t "

class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(1666, 879)
        Form.setStyleSheet("")
        self.gridLayout_4 = QtWidgets.QGridLayout(Form)
        self.gridLayout_4.setObjectName("gridLayout_4")
        self.gridLayout_3 = QtWidgets.QGridLayout()
        self.gridLayout_3.setObjectName("gridLayout_3")
        self.code_2 = QtWidgets.QLineEdit(Form)
        self.code_2.setObjectName("code_2")
        self.gridLayout_3.addWidget(self.code_2, 12, 8, 1, 1)
        self.size_2 = QtWidgets.QLineEdit(Form)
        self.size_2.setMinimumSize(QtCore.QSize(60, 0))
        self.size_2.setObjectName("size_2")
        self.gridLayout_3.addWidget(self.size_2, 19, 8, 1, 1, QtCore.Qt.AlignLeft)
        self.tcp_source_port_2 = QtWidgets.QLineEdit(Form)
        self.tcp_source_port_2.setObjectName("tcp_source_port_2")
        self.gridLayout_3.addWidget(self.tcp_source_port_2, 14, 4, 1, 1)
        self.label_8 = QtWidgets.QLabel(Form)
        self.label_8.setObjectName("label_8")
        self.gridLayout_3.addWidget(self.label_8, 6, 1, 1, 1)
        self.version = QtWidgets.QLabel(Form)
        self.version.setObjectName("version")
        self.gridLayout_3.addWidget(self.version, 7, 1, 1, 1, QtCore.Qt.AlignRight)
        self.header_length_2 = QtWidgets.QLineEdit(Form)
        self.header_length_2.setObjectName("header_length_2")
        self.gridLayout_3.addWidget(self.header_length_2, 8, 3, 1, 3)
        self.label_3 = QtWidgets.QLabel(Form)
        self.label_3.setAlignment(QtCore.Qt.AlignCenter)
        self.label_3.setObjectName("label_3")
        self.gridLayout_3.addWidget(self.label_3, 1, 8, 1, 1)
        self.source_mac = QtWidgets.QLabel(Form)
        self.source_mac.setObjectName("source_mac")
        self.gridLayout_3.addWidget(self.source_mac, 3, 1, 1, 3, QtCore.Qt.AlignRight)
        self.udp_source_port_2 = QtWidgets.QLineEdit(Form)
        self.udp_source_port_2.setObjectName("udp_source_port_2")
        self.gridLayout_3.addWidget(self.udp_source_port_2, 19, 3, 1, 2)
        self.source_mac_2 = QtWidgets.QLineEdit(Form)
        self.source_mac_2.setObjectName("source_mac_2")
        self.gridLayout_3.addWidget(self.source_mac_2, 3, 4, 1, 1)
        self.label_24 = QtWidgets.QLabel(Form)
        self.label_24.setObjectName("label_24")
        self.gridLayout_3.addWidget(self.label_24, 18, 1, 1, 1)
        self.destination_mac = QtWidgets.QLabel(Form)
        self.destination_mac.setObjectName("destination_mac")
        self.gridLayout_3.addWidget(self.destination_mac, 4, 1, 1, 3, QtCore.Qt.AlignRight)
        self.label_5 = QtWidgets.QLabel(Form)
        self.label_5.setObjectName("label_5")
        self.gridLayout_3.addWidget(self.label_5, 2, 1, 1, 3)
        self.type = QtWidgets.QLabel(Form)
        self.type.setObjectName("type")
        self.gridLayout_3.addWidget(self.type, 12, 1, 1, 2, QtCore.Qt.AlignRight)
        self.tcp_source_port = QtWidgets.QLabel(Form)
        self.tcp_source_port.setObjectName("tcp_source_port")
        self.gridLayout_3.addWidget(self.tcp_source_port, 14, 1, 1, 2, QtCore.Qt.AlignRight)
        self.size = QtWidgets.QLabel(Form)
        self.size.setObjectName("size")
        self.gridLayout_3.addWidget(self.size, 19, 7, 1, 1, QtCore.Qt.AlignRight)
        self.sequence_2 = QtWidgets.QLineEdit(Form)
        self.sequence_2.setObjectName("sequence_2")
        self.gridLayout_3.addWidget(self.sequence_2, 16, 4, 1, 4)
        self.label_15 = QtWidgets.QLabel(Form)
        self.label_15.setObjectName("label_15")
        self.gridLayout_3.addWidget(self.label_15, 11, 1, 1, 1)
        self.ttl_2 = QtWidgets.QLineEdit(Form)
        self.ttl_2.setObjectName("ttl_2")
        self.gridLayout_3.addWidget(self.ttl_2, 9, 2, 1, 5)
        self.protocol = QtWidgets.QLabel(Form)
        self.protocol.setObjectName("protocol")
        self.gridLayout_3.addWidget(self.protocol, 7, 8, 1, 1, QtCore.Qt.AlignRight)
        self.udp_destination_port = QtWidgets.QLabel(Form)
        self.udp_destination_port.setObjectName("udp_destination_port")
        self.gridLayout_3.addWidget(self.udp_destination_port, 20, 1, 1, 3, QtCore.Qt.AlignRight)
        self.destination_ip = QtWidgets.QLabel(Form)
        self.destination_ip.setObjectName("destination_ip")
        self.gridLayout_3.addWidget(self.destination_ip, 9, 8, 1, 3, QtCore.Qt.AlignRight)
        self.header_length = QtWidgets.QLabel(Form)
        self.header_length.setObjectName("header_length")
        self.gridLayout_3.addWidget(self.header_length, 8, 1, 1, 2)
        self.ttl = QtWidgets.QLabel(Form)
        self.ttl.setObjectName("ttl")
        self.gridLayout_3.addWidget(self.ttl, 9, 1, 1, 1, QtCore.Qt.AlignRight)
        self.type_2 = QtWidgets.QLineEdit(Form)
        self.type_2.setObjectName("type_2")
        self.gridLayout_3.addWidget(self.type_2, 12, 3, 1, 4)
        self.destination_mac_2 = QtWidgets.QLineEdit(Form)
        self.destination_mac_2.setObjectName("destination_mac_2")
        self.gridLayout_3.addWidget(self.destination_mac_2, 4, 4, 1, 1)
        self.source_ip = QtWidgets.QLabel(Form)
        self.source_ip.setObjectName("source_ip")
        self.gridLayout_3.addWidget(self.source_ip, 8, 8, 1, 2, QtCore.Qt.AlignRight)
        self.tcp_destination_port = QtWidgets.QLabel(Form)
        self.tcp_destination_port.setObjectName("tcp_destination_port")
        self.gridLayout_3.addWidget(self.tcp_destination_port, 15, 1, 1, 3, QtCore.Qt.AlignRight)
        self.acknowledgment = QtWidgets.QLabel(Form)
        self.acknowledgment.setObjectName("acknowledgment")
        self.gridLayout_3.addWidget(self.acknowledgment, 14, 8, 1, 3, QtCore.Qt.AlignRight)
        self.code = QtWidgets.QLabel(Form)
        self.code.setObjectName("code")
        self.gridLayout_3.addWidget(self.code, 12, 7, 1, 1)
        self.label_19 = QtWidgets.QLabel(Form)
        self.label_19.setObjectName("label_19")
        self.gridLayout_3.addWidget(self.label_19, 13, 1, 1, 1)
        self.tcp_destination_port_2 = QtWidgets.QLineEdit(Form)
        self.tcp_destination_port_2.setObjectName("tcp_destination_port_2")
        self.gridLayout_3.addWidget(self.tcp_destination_port_2, 15, 4, 1, 1)
        self.version_2 = QtWidgets.QLineEdit(Form)
        self.version_2.setObjectName("version_2")
        self.gridLayout_3.addWidget(self.version_2, 7, 2, 1, 4)
        self.udp_source_port = QtWidgets.QLabel(Form)
        self.udp_source_port.setObjectName("udp_source_port")
        self.gridLayout_3.addWidget(self.udp_source_port, 19, 1, 1, 2, QtCore.Qt.AlignRight)
        self.udp_destination_port_2 = QtWidgets.QLineEdit(Form)
        self.udp_destination_port_2.setObjectName("udp_destination_port_2")
        self.gridLayout_3.addWidget(self.udp_destination_port_2, 20, 4, 1, 2)
        spacerItem = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.gridLayout_3.addItem(spacerItem, 1, 1, 1, 1)
        self.sequence = QtWidgets.QLabel(Form)
        self.sequence.setObjectName("sequence")
        self.gridLayout_3.addWidget(self.sequence, 16, 1, 1, 3, QtCore.Qt.AlignRight)
        spacerItem1 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.gridLayout_3.addItem(spacerItem1, 17, 1, 1, 1)
        spacerItem2 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.gridLayout_3.addItem(spacerItem2, 5, 1, 1, 1)
        spacerItem3 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.gridLayout_3.addItem(spacerItem3, 21, 1, 1, 1)
        spacerItem4 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.gridLayout_3.addItem(spacerItem4, 10, 1, 1, 1)
        self.data = QtWidgets.QLabel(Form)
        self.data.setObjectName("data")
        self.gridLayout_3.addWidget(self.data, 22, 1, 1, 1, QtCore.Qt.AlignLeft)
        self.data_2 = QtWidgets.QPlainTextEdit(Form)
        self.data_2.setMinimumSize(QtCore.QSize(300, 300))
        self.data_2.setObjectName("data_2")
        self.gridLayout_3.addWidget(self.data_2, 23, 1, 1, 11)
        spacerItem5 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_3.addItem(spacerItem5, 9, 0, 1, 1)
        self.checksum = QtWidgets.QLabel(Form)
        self.checksum.setObjectName("checksum")
        self.gridLayout_3.addWidget(self.checksum, 12, 11, 1, 1, QtCore.Qt.AlignRight)
        self.checksum_2 = QtWidgets.QLineEdit(Form)
        self.checksum_2.setObjectName("checksum_2")
        self.gridLayout_3.addWidget(self.checksum_2, 12, 12, 1, 2)
        self.acknowledgment_2 = QtWidgets.QLineEdit(Form)
        self.acknowledgment_2.setObjectName("acknowledgment_2")
        self.gridLayout_3.addWidget(self.acknowledgment_2, 14, 11, 1, 2)
        self.protocol_2 = QtWidgets.QLineEdit(Form)
        self.protocol_2.setObjectName("protocol_2")
        self.gridLayout_3.addWidget(self.protocol_2, 7, 9, 1, 3)
        self.etherent_protocol_2 = QtWidgets.QLineEdit(Form)
        self.etherent_protocol_2.setObjectName("etherent_protocol_2")
        self.gridLayout_3.addWidget(self.etherent_protocol_2, 3, 11, 1, 1)
        self.source_ip_2 = QtWidgets.QLineEdit(Form)
        self.source_ip_2.setObjectName("source_ip_2")
        self.gridLayout_3.addWidget(self.source_ip_2, 8, 10, 1, 2)
        self.destination_ip_2 = QtWidgets.QLineEdit(Form)
        self.destination_ip_2.setObjectName("destination_ip_2")
        self.gridLayout_3.addWidget(self.destination_ip_2, 9, 11, 1, 1)
        self.etherent_protocol = QtWidgets.QLabel(Form)
        self.etherent_protocol.setObjectName("etherent_protocol")
        self.gridLayout_3.addWidget(self.etherent_protocol, 3, 8, 1, 1, QtCore.Qt.AlignRight)
        spacerItem6 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.gridLayout_3.addItem(spacerItem6, 24, 1, 1, 1)
        self.gridLayout_4.addLayout(self.gridLayout_3, 0, 2, 1, 1)
        self.gridLayout_2 = QtWidgets.QGridLayout()
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.listWidget = QtWidgets.QListWidget(Form)
        self.listWidget.setMinimumSize(QtCore.QSize(550, 600))
        self.listWidget.setObjectName("listWidget")
        self.gridLayout_2.addWidget(self.listWidget, 2, 1, 1, 2)
        spacerItem7 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_2.addItem(spacerItem7, 2, 3, 1, 1)
        spacerItem8 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.gridLayout_2.addItem(spacerItem8, 1, 1, 1, 1)
        spacerItem9 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_2.addItem(spacerItem9, 2, 0, 1, 1)
        spacerItem10 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.gridLayout_2.addItem(spacerItem10, 3, 1, 1, 1)
        self.pushButton_2 = QtWidgets.QPushButton(Form)
        self.pushButton_2.setObjectName("pushButton_2")
        self.gridLayout_2.addWidget(self.pushButton_2, 4, 1, 1, 2, QtCore.Qt.AlignHCenter)
        self.label_2 = QtWidgets.QLabel(Form)
        self.label_2.setAlignment(QtCore.Qt.AlignCenter)
        self.label_2.setObjectName("label_2")
        self.gridLayout_2.addWidget(self.label_2, 0, 1, 1, 2)
        self.gridLayout_4.addLayout(self.gridLayout_2, 0, 1, 1, 1)
        self.gridLayout = QtWidgets.QGridLayout()
        self.gridLayout.setObjectName("gridLayout")
        spacerItem11 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout.addItem(spacerItem11, 3, 3, 1, 1)
        spacerItem12 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.gridLayout.addItem(spacerItem12, 1, 1, 1, 1)
        spacerItem13 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout.addItem(spacerItem13, 3, 0, 1, 1)
        self.radioButton = QtWidgets.QRadioButton(Form)
        self.radioButton.setObjectName("radioButton")
        self.gridLayout.addWidget(self.radioButton, 3, 1, 1, 1)
        self.checkBox_3 = QtWidgets.QCheckBox(Form)
        self.checkBox_3.setObjectName("checkBox_3")
        self.gridLayout.addWidget(self.checkBox_3, 6, 1, 1, 1)
        self.checkBox_2 = QtWidgets.QCheckBox(Form)
        self.checkBox_2.setObjectName("checkBox_2")
        self.gridLayout.addWidget(self.checkBox_2, 5, 1, 1, 1)
        self.label_4 = QtWidgets.QLabel(Form)
        self.label_4.setMinimumSize(QtCore.QSize(147, 50))
        self.label_4.setObjectName("label_4")
        self.gridLayout.addWidget(self.label_4, 2, 1, 1, 2)
        self.pushButton_3 = QtWidgets.QPushButton(Form)
        self.pushButton_3.setObjectName("pushButton_3")
        self.gridLayout.addWidget(self.pushButton_3, 12, 2, 1, 1, QtCore.Qt.AlignHCenter)
        self.pushButton = QtWidgets.QPushButton(Form)
        self.pushButton.setObjectName("pushButton")
        self.gridLayout.addWidget(self.pushButton, 12, 1, 1, 1, QtCore.Qt.AlignHCenter)
        self.checkBox = QtWidgets.QCheckBox(Form)
        self.checkBox.setObjectName("checkBox")
        self.gridLayout.addWidget(self.checkBox, 4, 1, 1, 1)
        spacerItem14 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout.addItem(spacerItem14, 8, 1, 1, 1)
        spacerItem15 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.gridLayout.addItem(spacerItem15, 11, 1, 1, 1)
        self.label_30 = QtWidgets.QLabel(Form)
        self.label_30.setObjectName("label_30")
        self.gridLayout.addWidget(self.label_30, 9, 1, 1, 1)
        self.lineEdit_18 = QtWidgets.QLineEdit(Form)
        self.lineEdit_18.setObjectName("lineEdit_18")
        self.gridLayout.addWidget(self.lineEdit_18, 10, 1, 1, 1)
        self.label = QtWidgets.QLabel(Form)
        self.label.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        self.label.setObjectName("label")
        self.gridLayout.addWidget(self.label, 0, 1, 1, 1)
        self.gridLayout_4.addLayout(self.gridLayout, 0, 0, 1, 1)
        spacerItem16 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_4.addItem(spacerItem16, 0, 3, 1, 1)
        self.version.setBuddy(self.version_2)
        self.source_mac.setBuddy(self.source_mac_2)
        self.destination_mac.setBuddy(self.destination_mac_2)
        self.type.setBuddy(self.type_2)
        self.tcp_source_port.setBuddy(self.tcp_source_port_2)
        self.size.setBuddy(self.size_2)
        self.protocol.setBuddy(self.protocol_2)
        self.udp_destination_port.setBuddy(self.udp_destination_port_2)
        self.destination_ip.setBuddy(self.destination_ip_2)
        self.header_length.setBuddy(self.header_length_2)
        self.ttl.setBuddy(self.ttl_2)
        self.source_ip.setBuddy(self.source_ip_2)
        self.tcp_destination_port.setBuddy(self.tcp_destination_port_2)
        self.acknowledgment.setBuddy(self.acknowledgment_2)
        self.code.setBuddy(self.code_2)
        self.udp_source_port.setBuddy(self.udp_source_port_2)
        self.sequence.setBuddy(self.sequence_2)
        self.data.setBuddy(self.data_2)
        self.checksum.setBuddy(self.checksum_2)

        self.retranslateUi(Form)
        self.radioButton.clicked['bool'].connect(self.checkBox.setChecked)
        self.radioButton.clicked['bool'].connect(self.checkBox_2.setChecked)
        self.radioButton.clicked['bool'].connect(self.checkBox_3.setChecked)
        QtCore.QMetaObject.connectSlotsByName(Form)

        # assign the buttons
        self.pushButton.clicked.connect(self.startSniffing)
        self.pushButton_2.clicked.connect(self.save)
        self.pushButton_3.clicked.connect(self.stopSniffing)
        
        # make radio button initially slected
        self.radioButton.setChecked(True)
        self.checkBox.setChecked(True)
        self.checkBox_2.setChecked(True)
        self.checkBox_3.setChecked(True)
        
        # all radioButton checking mechanism
        self.checkBox.clicked.connect(self.runChecker)
        self.checkBox_2.clicked.connect(self.runChecker)
        self.checkBox_3.clicked.connect(self.runChecker)

        # item selection mechanism
        self.listWidget.itemClicked.connect(self.selectItem)

        self.listWidget.addItem("Protocol \t\t Source \t\t Destination")

        # List that holds every recieved data
        self.sniffedPacketsList = []

        # Setting the IP text to empty string
        self.lineEdit_18.setText("")

        # Initializing a thread holder with 0 for the class
        self.thread = 0

        
    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Simple Packet Sniffer"))
        self.label_8.setText(_translate("Form", "IPv4 Data :"))
        self.version.setText(_translate("Form", "Version :"))
        self.label_3.setText(_translate("Form", "Packet Detail"))
        self.source_mac.setText(_translate("Form", "Source MAC : "))
        self.label_24.setText(_translate("Form", "UDP Data :"))
        self.destination_mac.setText(_translate("Form", "Destination MAC :"))
        self.label_5.setText(_translate("Form", "Ethernet Frame Data :"))
        self.type.setText(_translate("Form", "Type :"))
        self.tcp_source_port.setText(_translate("Form", "Source Port :"))
        self.size.setText(_translate("Form", "Size :"))
        self.label_15.setText(_translate("Form", "ICMP Data :"))
        self.protocol.setText(_translate("Form", "Protocol :"))
        self.udp_destination_port.setText(_translate("Form", "Destination Port :"))
        self.destination_ip.setText(_translate("Form", "Destination IP :"))
        self.header_length.setText(_translate("Form", "Header Length :"))
        self.ttl.setText(_translate("Form", "TTL :"))
        self.source_ip.setText(_translate("Form", "Source IP :"))
        self.tcp_destination_port.setText(_translate("Form", "Destination Port :"))
        self.acknowledgment.setText(_translate("Form", "Acknowledgment :"))
        self.code.setText(_translate("Form", "Code :"))
        self.label_19.setText(_translate("Form", "TCP Data :"))
        self.udp_source_port.setText(_translate("Form", "Source Port :"))
        self.sequence.setText(_translate("Form", "Sequence :"))
        self.data.setText(_translate("Form", "Data :"))
        self.checksum.setText(_translate("Form", "Checksum :"))
        self.etherent_protocol.setText(_translate("Form", "Ethernet Protocol :"))
        self.pushButton_2.setText(_translate("Form", "Save"))
        self.label_2.setText(_translate("Form", "Sniffed Packets"))
        self.radioButton.setText(_translate("Form", "ALL"))
        self.checkBox_3.setText(_translate("Form", "UDP"))
        self.checkBox_2.setText(_translate("Form", "TCP"))
        self.label_4.setText(_translate("Form", "Select Protocol Type/s To Sniff"))
        self.pushButton_3.setText(_translate("Form", "Stop"))
        self.pushButton.setText(_translate("Form", "Start"))
        self.checkBox.setText(_translate("Form", "ICMP"))
        self.label_30.setText(_translate("Form", "Specific IP:"))
        self.label.setText(_translate("Form", "Inputs"))

    def runChecker(self):
        if self.checkBox.isChecked() and self.checkBox_2.isChecked() and self.checkBox_3.isChecked():
            self.radioButton.setChecked(True)
        else:
            self.radioButton.setChecked(False)

    def addItemToList(self, item):
        self.listWidget.addItem(item)

    def clearFields(self, num):
        if num == 2:
            self.tcp_source_port_2.setText("")
            self.tcp_destination_port_2.setText("")
            self.sequence_2.setText("")
            self.acknowledgment_2.setText("")
            self.udp_source_port_2.setText("")
            self.udp_destination_port_2.setText("")
            self.size_2.setText("")
        
        elif num == 3:
            self.type_2.setText("")
            self.code_2.setText("")
            self.checksum_2.setText("")
            self.udp_source_port_2.setText("")
            self.udp_destination_port_2.setText("")
            self.size_2.setText("")
        elif num == 4:
            self.type_2.setText("")
            self.code_2.setText("")
            self.checksum_2.setText("")
            self.data_2.setPlainText("")
            self.tcp_source_port_2.setText("")
            self.tcp_destination_port_2.setText("")
            self.sequence_2.setText("")
            self.acknowledgment_2.setText("")


    def selectItem(self,item):

        index = int(item.text()[0]) - 1
        selectedItem = self.sniffedPacketsList[index]

        self.source_mac_2.setText(selectedItem.src_mac)
        self.destination_mac_2.setText(selectedItem.dest_mac)
        self.etherent_protocol_2.setText(str(selectedItem.eth_proto))

        self.version_2.setText(str(selectedItem.version))
        self.header_length_2.setText(str(selectedItem.header_length))
        self.ttl_2.setText(str(selectedItem.ttl))
        self.protocol_2.setText(str(selectedItem.proto))
        self.source_ip_2.setText(selectedItem.src)
        self.destination_ip_2.setText(selectedItem.target)

        print("second status in select item")
        print(selectedItem.status)

        if selectedItem.status == 4:
            self.clearFields(4)
            self.udp_source_port_2.setText(str(selectedItem.src_port))
            self.udp_destination_port_2.setText(str(selectedItem.dest_port))
            self.size_2.setText(str(selectedItem.size))

        if selectedItem.status == 3:
            self.clearFields(3)
            self.tcp_source_port_2.setText(str(selectedItem.src_port))
            self.tcp_destination_port_2.setText(str(selectedItem.dest_port))
            self.sequence_2.setText(str(selectedItem.sequence))
            self.acknowledgment_2.setText(str(selectedItem.acknowledgement))
            self.data_2.setPlainText(self.format_multi_line(DATA_TAB, selectedItem.data))

        if selectedItem.status == 2:
            self.clearFields(2)
            self.type_2.setText(str(selectedItem.icmp_type))
            self.code_2.setText(str(selectedItem.code))
            self.checksum_2.setText(str(selectedItem.checksum))
            self.data_2.setPlainText(self.format_multi_line(DATA_TAB, selectedItem.data))


        # else:
        #     self.data_2.setPlainText(self.format_multi_line("DATA_TAB", selectedItem.data))
        

    def startSniffingThread(self):
        self.status = True
        print("Started Sniffing")
        protocolList = []
        if self.radioButton.isChecked():
            protocolList.append(0)            
            protocolList.append(1)            
            protocolList.append(6)            
            protocolList.append(17)

        else:
            if self.checkBox.isChecked():
                protocolList.append(1)  
            
            if self.checkBox_2.isChecked():
                protocolList.append(6) 

            if self.checkBox_3.isChecked():
                protocolList.append(17) 
            
        print(protocolList)

        if not(len(protocolList) < 1):
            try:
                sniffObj = SnifferClass.Sniffer(protocolList,self.lineEdit_18.text())
                while self.status:
                    newSniff = sniffObj.sniffOne()
                    if newSniff != None:
                        # print(self.newSniff.getRepresentation())
                        print("status")
                        print(newSniff.status)
                        self.sniffedPacketsList.append(newSniff)
                        data = str(len(self.sniffedPacketsList)) + ". " +  newSniff.getRepresentation()
                        print(data)
                        # self.addItemToList(data)
                        self.listWidget.addItem(data)
                        #time.sleep(10)

                sys.exit()
            except Exception as err:
                print(err)
                print("Error: unable to start thread")
        else:
            print("protocolList length is 0")

    def startSniffing(self):
        if self.thread == 0:
            self.thread = threading.Thread(target=self.startSniffingThread, args=())
            self.thread.start()

        else:
            pass
            
    def stopSniffing(self):
        print("stop sniffing called")
        self.status = False
        print("value of stop variable is: " + str(self.status))
        self.thread = 0

    def save(self):
        with open("sniffes.txt", "w") as f:
            for index in range(len(self.sniffedPacketsList)):
                f.write(str(index + 1) + ". " +str(self.sniffedPacketsList[index].getInformation()))

            f.close()

    def format_multi_line(self,prefix, string, size=80):
        size -= len(prefix)
        if isinstance(string, bytes):
            string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
            if size % 2:
                size -= 1
        
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Form = QtWidgets.QWidget()
    ui = Ui_Form()
    ui.setupUi(Form)
    Form.show()
    sys.exit(app.exec_())
