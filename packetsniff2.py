# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '.\PacketSniffer.ui'
#
# Created by: PyQt5 UI code generator 5.15.1
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.

import SnifferClass
import _thread
from PyQt5 import QtCore, QtGui, QtWidgets
import time


class Ui_Form(object):


    def setupUi(self, Form):
        self.stop = False
        Form.setObjectName("Form")
        Form.resize(1082, 512)
        self.gridLayout_4 = QtWidgets.QGridLayout(Form)
        self.gridLayout_4.setObjectName("gridLayout_4")
        self.gridLayout = QtWidgets.QGridLayout()
        self.gridLayout.setObjectName("gridLayout")
        self.checkBox_2 = QtWidgets.QCheckBox(Form)
        self.checkBox_2.setObjectName("checkBox_2")
        self.gridLayout.addWidget(self.checkBox_2, 5, 1, 1, 1)
        self.radioButton = QtWidgets.QRadioButton(Form)
        self.radioButton.setObjectName("radioButton")
        self.gridLayout.addWidget(self.radioButton, 3, 1, 1, 1)
        self.checkBox_3 = QtWidgets.QCheckBox(Form)
        self.checkBox_3.setObjectName("checkBox_3")
        self.gridLayout.addWidget(self.checkBox_3, 6, 1, 1, 1)
        self.pushButton = QtWidgets.QPushButton(Form)
        self.pushButton.setObjectName("pushButton")
        self.gridLayout.addWidget(self.pushButton, 8, 1, 1, 1, QtCore.Qt.AlignHCenter)
        self.label_4 = QtWidgets.QLabel(Form)
        self.label_4.setMinimumSize(QtCore.QSize(147, 50))
        self.label_4.setObjectName("label_4")
        self.gridLayout.addWidget(self.label_4, 2, 1, 1, 2)
        self.label = QtWidgets.QLabel(Form)
        self.label.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        self.label.setObjectName("label")
        self.gridLayout.addWidget(self.label, 0, 1, 1, 1)
        self.pushButton_3 = QtWidgets.QPushButton(Form)
        self.pushButton_3.setObjectName("pushButton_3")
        self.gridLayout.addWidget(self.pushButton_3, 8, 2, 1, 1, QtCore.Qt.AlignHCenter)
        self.checkBox = QtWidgets.QCheckBox(Form)
        self.checkBox.setObjectName("checkBox")
        self.gridLayout.addWidget(self.checkBox, 4, 1, 1, 1)
        spacerItem = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.gridLayout.addItem(spacerItem, 7, 1, 1, 1)
        spacerItem1 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.gridLayout.addItem(spacerItem1, 1, 1, 1, 1)
        spacerItem2 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout.addItem(spacerItem2, 3, 0, 1, 1)
        spacerItem3 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout.addItem(spacerItem3, 3, 3, 1, 1)
        self.gridLayout_4.addLayout(self.gridLayout, 0, 0, 1, 1)
        self.gridLayout_3 = QtWidgets.QGridLayout()
        self.gridLayout_3.setObjectName("gridLayout_3")
        self.plainTextEdit = QtWidgets.QPlainTextEdit(Form)
        self.plainTextEdit.setMinimumSize(QtCore.QSize(350, 430))
        self.plainTextEdit.setObjectName("plainTextEdit")
        self.gridLayout_3.addWidget(self.plainTextEdit, 2, 1, 1, 1)
        spacerItem4 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_3.addItem(spacerItem4, 2, 0, 1, 1)
        self.label_3 = QtWidgets.QLabel(Form)
        self.label_3.setAlignment(QtCore.Qt.AlignCenter)
        self.label_3.setObjectName("label_3")
        self.gridLayout_3.addWidget(self.label_3, 0, 1, 1, 1)
        spacerItem5 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_3.addItem(spacerItem5, 2, 2, 1, 1)
        spacerItem6 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.gridLayout_3.addItem(spacerItem6, 1, 1, 1, 1)
        spacerItem7 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.gridLayout_3.addItem(spacerItem7, 3, 1, 1, 1)
        self.gridLayout_4.addLayout(self.gridLayout_3, 0, 2, 1, 1)
        self.gridLayout_2 = QtWidgets.QGridLayout()
        self.gridLayout_2.setObjectName("gridLayout_2")
        spacerItem8 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.gridLayout_2.addItem(spacerItem8, 1, 1, 1, 1)
        self.listWidget = QtWidgets.QListWidget(Form)
        self.listWidget.setMinimumSize(QtCore.QSize(350, 400))
        self.listWidget.setObjectName("listWidget")
        self.gridLayout_2.addWidget(self.listWidget, 2, 1, 1, 2)
        spacerItem9 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_2.addItem(spacerItem9, 2, 3, 1, 1)
        self.pushButton_2 = QtWidgets.QPushButton(Form)
        self.pushButton_2.setObjectName("pushButton_2")
        self.gridLayout_2.addWidget(self.pushButton_2, 4, 1, 1, 2, QtCore.Qt.AlignHCenter)
        spacerItem10 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_2.addItem(spacerItem10, 2, 0, 1, 1)
        self.label_2 = QtWidgets.QLabel(Form)
        self.label_2.setAlignment(QtCore.Qt.AlignCenter)
        self.label_2.setObjectName("label_2")
        self.gridLayout_2.addWidget(self.label_2, 0, 1, 1, 2, QtCore.Qt.AlignHCenter)
        spacerItem11 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.gridLayout_2.addItem(spacerItem11, 3, 1, 1, 1)
        self.gridLayout_4.addLayout(self.gridLayout_2, 0, 1, 1, 1)

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

        # List that holds every recieved data
        self.sniffedPacketsList = []


    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Simple Packet Sniffer"))
        self.checkBox_2.setText(_translate("Form", "TCP"))
        self.radioButton.setText(_translate("Form", "ALL"))
        self.checkBox_3.setText(_translate("Form", "UDP"))
        self.pushButton.setText(_translate("Form", "Start"))
        self.label_4.setText(_translate("Form", "Select Protocol Type/s To Sniff"))
        self.label.setText(_translate("Form", "Inputs"))
        self.pushButton_3.setText(_translate("Form", "Stop"))
        self.checkBox.setText(_translate("Form", "ICMP"))
        self.label_3.setText(_translate("Form", "Packet Detail"))
        self.pushButton_2.setText(_translate("Form", "Save"))
        self.label_2.setText(_translate("Form", "Sniffed Packets"))

    def runChecker(self):
        if self.checkBox.isChecked() and self.checkBox_2.isChecked() and self.checkBox_3.isChecked():
            self.radioButton.setChecked(True)
        else:
            self.radioButton.setChecked(False)

    def addItemToList(self, item):
        self.listWidget.addItem(item)

    def selectItem(self,item):
        index = int(item.text()[0]) - 1
        description = self.sniffedPacketsList[index].getInformation()
        
        self.plainTextEdit.setPlainText(description)

    def startSniffing(self):
        self.status = True
        self.count = 0
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
                self.sniffObj = SnifferClass.Sniffer(protocolList,self)
                # while self.status:
                self.newSniff = self.sniffObj.sniffOne()
                print(self.newSniff.getRepresentation())
                self.sniffedPacketsList.append(self.newSniff)
                data = str(self.count + 1) + "." +  self.newSniff.getRepresentation()
                print(data)
                # self.addItemToList(data)
                self.listWidget.addItem(data)
                self.count += 1
                # time.sleep(10)
            except Exception as err:
                print(err)
                print("Error: unable to start thread")
        else:
            print("protocolList length is 0")
            
    def stopSniffing(self):
        print("stop sniffing called")
        self.status = False
        print("value of stop variable is: " + str(self.status))

    def save(self):
        with open("sniffes.txt", "w") as f:
            for index in range(len(self.sniffedPacketsList)):
                f.write(str(index + 1) + ". " +str(self.sniffedPacketsList[index].getInformation()))

            f.close()


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Form = QtWidgets.QWidget()
    ui = Ui_Form()
    ui.setupUi(Form)
    Form.show()

    sys.exit(app.exec_())
