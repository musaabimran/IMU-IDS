from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTabWidget, QPlainTextEdit
import sys
import threading
import scapy.all as scapy 
from argparse import RawTextHelpFormatter
import argparse
from scapy.layers import http, inet, dhcp, dns, tls
from scapy.layers.l2 import Ether 
import time #for seleeping system 


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        # Set window properties
        self.setWindowTitle("IMU-IDS")
        self.setFixedSize(1200, 700)

        # Create main widget and layout
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)

        # Create button
        button = QPushButton("Make yourself secure with IMU-IDS")
        button.setStyleSheet("""
            background-color: #4285f4;
            color: #fff;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
        """)
        button.setFont(QFont("Arial", 16))
        button.clicked.connect(self.show_tabs)
    
        # Create button
        exit_button = QPushButton("Exit")
        exit_button.setStyleSheet("""
            background-color: #4285f4;
            color: #fff;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
        """)
        exit_button.setFont(QFont("Arial", 16))
        exit_button.clicked.connect(self.show_tabs)
        exit_button.clicked.connect(QApplication.instance().quit)

        main_layout.addWidget(button)
        main_layout.addWidget(exit_button)

        # Create tab widget and add to main layout
        self.tab_widget = QTabWidget()
        self.tab_widget.hide()
        main_layout.addWidget(self.tab_widget)

        # Create tabs
        tab1 = QWidget()
        tab2 = QWidget()
        tab3 = QWidget()
        
        self.tab_widget.addTab(tab1, "Live IDS")
        self.tab_widget.addTab(tab2, "Pre IDS")
        self.tab_widget.addTab(tab3, "ML IDS")
   
        # Set font for section labels
        font = QFont()
        font.setPointSize(16)

        # Create first section
        section1_layout = QVBoxLayout()
        section1_label = QLabel("This is section 1")
        section1_label.setAlignment(Qt.AlignCenter)
        section1_label.setFont(font)
        section1_layout.addWidget(section1_label)
        tab1.setLayout(section1_layout)
        
        # Create output for section 1
        section1_output = QPlainTextEdit()
        section1_layout.addWidget(section1_output)
        section1_output.setReadOnly(True)

        # the code for the section 1 the live IDS
        #this function is used for sniffing
        def sniff(interface, filters):
            scapy.sniff(iface=interface, store=False,
                        prn=process_sniffed_packets, filter=filters)  

        def process_sniffed_packets(packet):
            print_alert_on_screen(packet)
            time.sleep(1)
            print(packet)

        def print_alert_on_screen(alert):
            section1_output.appendPlainText(alert.summary())

        def run_section1(section1_output): 

            thread_sniff = threading.Thread(target=sniff, args=(None,None))
            thread_sniff.start()  
            # output = "[+] alert "
            # section1_output.appendPlainText(output)

                   
        # Create thread for section 1
        thread = threading.Thread(target=run_section1, args=(section1_output,))
        thread.start()

        # making widget for section 1
        section1_layout.addWidget(section1_output)

        # Create second section
        section2_layout = QVBoxLayout()
        section2_label = QLabel("This is section 2")
        section2_label.setAlignment(Qt.AlignCenter)
        section2_label.setFont(font)
        section2_layout.addWidget(section2_label)
        tab2.setLayout(section2_layout)

        # Create third section
        section3_layout = QVBoxLayout()
        section3_label = QLabel("This is section 3")
        section3_label.setAlignment(Qt.AlignCenter)
        section3_label.setFont(font)
        section3_layout.addWidget(section3_label)
        tab3.setLayout(section3_layout)


        # Add main widget to the main window
        self.setCentralWidget(main_widget)

        # Set stylesheet
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QLabel {
                color: #333;
            }
            QTabWidget::pane {
                background-color: #fff;
            }
            QTabWidget::tab-bar {
                alignment: center;
            }
            QTabBar::tab {
                color: #333;
                background-color: #fff;
                border: none;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
                padding: 10px;
            }
            QTabBar::tab:selected {
                background-color: #000000;
                color: #fff;
            }
            QPushButton {
                font-size: 16px;
            }
        """)

    def show_tabs(self):
        self.tab_widget.show()

if __name__ == '__main__':
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec()
