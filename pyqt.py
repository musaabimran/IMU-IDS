from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QTextEdit
from PySide6.QtWidgets import QScrollArea
from PySide6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QDialog
import sys
import threading
import scapy.all as scapy 
from argparse import RawTextHelpFormatter
import argparse
from scapy.layers import http, inet, dhcp, dns, tls
from scapy.layers.l2 import Ether 
import time #for seleeping system 

Live_Ids_String = "Live IDS"
Pre_Build_String = "Pre Build IDS"
ML_Based_String = "ML based"
 

class SubWindow(QDialog):
    def __init__(self,arg, parent=None):
        self.args = arg
        super().__init__(parent)
        self.setWindowTitle("IMU-IDS")
        self.setMinimumSize(900, 700)
        self.setStyleSheet('''
            QDialog {
                background-color: #f5f5f5;
            }
            QLabel {
                color: #333;
                font-size: 18px;
                padding: 10px;
            }
            QScrollBar:vertical {
                background: #f5f5f5;
                width: 10px;
                margin: 0px 0px 0px 0px;
            }
            QScrollBar::handle:vertical {
                background: #ccc;
                min-height: 20px;
                border-radius: 5px;
            }
        ''')


        # Create widget to display information
        self.text_edit = QLabel(arg)
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(self.text_edit)
        layout = QVBoxLayout()
        layout.addWidget(scroll_area)
        self.setLayout(layout)
    def add_information(self, info):
        # Append information to the text edit widget
        if self.args == ML_Based_String:
            print("Here we are oging to do ML Processing")
        elif self.args == Pre_Build_String:
            print("This is Pre build IDS")
        elif self.args == Live_Ids_String:
            print("This is LIVEE IDS")
        self.text_edit.setText(self.text_edit.text() + "\n" + str(info))

        



class MainWindow(QMainWindow):
    def __init__(self):
        subwindow = None
        super().__init__()

        # Set window properties
        self.setWindowTitle("IMU IDS")
        self.setFixedSize(400, 300)

        # Create main widget and layout
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)

        # Create button
        button = QPushButton("Live Intrusion Detection Packet")
        button.clicked.connect(self.live_ids)
        main_layout.addWidget(button)

        # Create button
        button1 = QPushButton("Pre Build Intrusion Detection")
        button1.clicked.connect(self.pre_build)
        main_layout.addWidget(button1)

        # Create button
        button2 = QPushButton("ML Based Intrusion Detection")
        button2.clicked.connect(self.ml_based_ids)
        main_layout.addWidget(button2)
        
        # exit button
        button3 = QPushButton("Exit")
        button3.clicked.connect(self.exit)
        main_layout.addWidget(button3)
        

        # Add main widget to the main window
        self.setCentralWidget(main_widget)

        # Set stylesheet
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QPushButton {
                background-color: #4285f4;
                color: #fff;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
            }
        """)
    def exit(self):
        QApplication.instance().quit
        sys.exit()

        
    def live_ids(self):
        print("Live Intrusion Detectione")
        self.sub_window = SubWindow(Live_Ids_String)
        self.start_sub_window()
        

    def pre_build(self):
        print("Pre Build Intrusion Detectione")
        self.sub_window = SubWindow(Pre_Build_String)
        self.start_sub_window()

    def ml_based_ids(self):
        print("This is Ml based ids made by musaab oone and only one ")
        self.sub_window = SubWindow(ML_Based_String)
        self.start_sub_window()
        
    def start_sub_window(self):
        self.sub_window.exec()

        # sniff the packet and will do all stuff in process_sniffed_packets
        thread_sniff = threading.Thread(target=self.sniff, args=(None,None))
        thread_sniff.start() 

    #this function is used for sniffing
    def sniff(self,interface, filters):
        scapy.sniff(iface=interface, store=False,
                    prn=self.process_sniffed_packets, filter=filters)  

    def process_sniffed_packets(self,packet):
        time.sleep(1)
        print(packet)
        self.sub_window.add_information(packet)

       


if __name__ == '__main__':
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec()
