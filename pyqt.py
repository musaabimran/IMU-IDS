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
import time  # for seleeping system

Live_Ids_String = "Live IDS"
Pre_Build_String = "Pre Build IDS"
ML_Based_String = "ML based"


class SubWindow(QDialog):
    def __init__(self, arg, parent=None):
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

    def add_information(self, packet):
        alert_flag = False
        alert = ''

        # Append information to the text edit widget
        if self.args == ML_Based_String:
            print("Here we are oging to do ML Processing")
        elif self.args == Pre_Build_String:
            print("This is Pre build IDS")
        elif self.args == Live_Ids_String:

            if packet.haslayer(http.HTTPRequest):
                if self.live_sql_injection_test(packet):
                    alert_flag = True
                    alert += '[+] Possible SQL Injection [+]\n'

                if self.live_command_injection_test(packet):
                    alert_flag = True
                    alert += '[+] Possible Command Injection [+]\n'

                if self.live_xpath_injection_test(packet):
                    alert_flag = True
                    alert += '[+] Possible XPath Injection [+]\n'

                if self.live_xslt_injection_test(packet):
                    alert_flag = True
                    alert += '[+] Possible XSLT Injection [+]\n'

                if self.live_xxe_injection_test(packet):
                    alert_flag = True
                    alert += '[+] Possible XXE Injection [+]\n'

                if self.live_js_injection_test(packet):
                    alert_flag = True
                    alert += '[+] Possible JS Injection [+]\n'

                if self.live_html_injection_test(packet):
                    alert_flag = True
                    alert += '[+] Possible HTML Injection [+]\n'

                if self.live_get_login_info(packet):
                    alert_flag = True
                    alert += '[+] Possible GET Login Info [+]\n'

            print("This is LIVEE IDS")

        # if alert generated print that
        if alert_flag:
            self.text_edit.setText(self.text_edit.text(
            ) + "\n -------------------------------------------------------------------------------- \n")
            self.text_edit.setText(self.text_edit.text() + "\n" + (alert))
            self.text_edit.setText(self.text_edit.text() + "\n" + str(packet))
            self.text_edit.setText(self.text_edit.text(
            ) + "\n -------------------------------------------------------------------------------- \n")

    # --------------------------------------------
    # --------------- live IDS -------------------
    # --------------------------------------------

    # --------------------------------------------
    # --------------- Html injection -------------
    # --------------------------------------------

    def live_html_injection_test(self, packet):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            # Testing if there is some HTML injection Possible
            html_injections = ["<h1>", "<h2>", "<h1>", "%3C%2F", "%3CHTML%3E", "%3C%2FHTML%3E", "%3E", "%3CH1%3E", "%3C%2FH1%3E", "<HTML>", "</HTML>", "%3CH2%3E",
                               "%3C%2FH2%3E", "%3CH3%3E", "%3C%2FH3%3E", "%3CH4%3E", "%3C%2FH4%3E", "%3CH5%3E", "%3C%2FH5%3E", "%3CH6%3E", "%3C%2FH6%3E", "</h2>", "%3CBR%3E", "%3CHR%3E"]
            for html_injection in html_injections:
                try:
                    if html_injection in load.decode("utf-8"):
                        return True
                except:
                    break

            return False

    # --------------------------------------------
    # --------------- SQL injection -------------
    # --------------------------------------------

    def live_sql_injection_test(self, packet):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            # Testing if there is some HTML injection Possible
            sql_injections = ["page.asp?id=1 or 1=1",
                              "page.asp?id=1' or 1=1",
                              "page.asp?id=1\" or 1=1",
                              "page.asp?id=1 and 1=2",
                              "%22page.asp%3Fid%3D1%20or%201%3D1%22%2C%0A",
                              "page.asp%3Fid%3D1%27%20or%201%3D1",
                              "page.asp%3Fid%3D1%20or%201%3D1",
                              "page.asp%3Fid%3D1%22%20or%201%3D1",
                              "page.asp%3Fid%3D1%20and%201%3D2",
                              "%22",
                              "\"",
                              "'",
                              "%27",
                              "#",
                              "%23",
                              ";",
                              "%3B",
                              "%%2727",
                              "%25%27"
                              ]
            for sql_injection in sql_injections:
                try:
                    if sql_injection in load.decode("utf-8"):
                        return True
                except:
                    break

            return False

    # --------------------------------------------
    # --------------- XXE injection -------------
    # --------------------------------------------

    def live_xxe_injection_test(self, packet):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            # Testing if there is some xee injection Possible
            xxe_injections = ["<!DOCTYPE",
                              "%3C%21DOCTYPE",
                              "[<!ENTITY",
                              "%5B%3C%21ENTITY",
                              "%5D%3E",
                              "]>",
                              "<?xml",
                              "%3C%3Fxml"
                              ]
            for xxe_injection in xxe_injections:
                try:
                    if xxe_injection in load.decode("utf-8"):
                        return True
                except:
                    break

            return False

    # --------------------------------------------
    # --------------- JS injection -------------
    # --------------------------------------------

    def live_js_injection_test(self, packet):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load

            # Testing if there is some HTML injection Possible
            js_injections = ["<script>",
                             "%3Cscript%3E",
                             "</script>",
                             "%3C%2Fscript%3E",
                             "document.location",
                             "<?php",
                             "%3C%3Fphp",
                             "<img",
                             "%3Cimg",
                             "console.log",
                             "alert",
                             "alert(",
                             "alert%28",
                             "eval",
                             "<svg",
                             "%3Csvg",
                             "<div",
                             "%3Cdiv"
                             ]
            for js_injection in js_injections:
                try:
                    if js_injection in load.decode("utf-8"):
                        return True
                except:
                    break

            return False

    # --------------------------------------------
    # --------------- XPath Injection -------------
    # --------------------------------------------

    def live_xpath_injection_test(self, packet):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            # Testing if there is some xpath_injection_test Possible
            xpath_injections = [
                "' or '1'='1",
                "%27%20or%20%271%27%3D%271",
                "' or ''='",
                "%27%20or%20%27%27%3D%27",
                "' or 1=1 or 'x'='y",
                "%27%20or%201%3D1%20or%20%27x%27%3D%27y",
                "/",
                "%2F",
                "//",
                "%2F%2F",
                "//*",
                "%2F%2F%2A",
                "*/*",
                "%2A%2F%2A",
                "@*",
                "%40%2A"

            ]
            for xpath_injection in xpath_injections:
                try:
                    if xpath_injection in load.decode("utf-8"):
                        return True
                except:
                    break

            return False

    # --------------------------------------------
    # --------------- Command injection -------------
    # --------------------------------------------

    def live_command_injection_test(self, packet):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            # Testing if there is some HTML injection Possible
            command_injections = [
                "cat \\",
                "cat%20%2F",
                ":root",
                "%3Aroot",
                "/bin",
                "%2Fbin",
                "/sh",
                "%2Fsh",
                "/dev",
                "%2Fdev",
                "/root",
                "%2Froot",
                "/",
                "%2F"
            ]
            for command_injection in command_injections:
                try:
                    if command_injection in load.decode("utf-8"):
                        return True
                except:
                    break

            return False

    # --------------------------------------------
    # --------------- XSLT injection -------------
    # --------------------------------------------

    def live_xslt_injection_test(self, packet):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            # Testing if there is some xslt_injection_test
            xslt_injections = [
                "<xsl:",
                "%3Cxsl%3A",
                "<xsl",
                "%3Cxsl"
            ]
            for xslt_injection in xslt_injections:
                try:
                    if xslt_injection in load.decode("utf-8"):
                        return True
                except:
                    break

            return False

    # --------------------------------------------
    # --------------- Possible Login -------------
    # --------------------------------------------

    def live_get_login_info(self, packet):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["username", "user", "password",
                        "pass", "login", "eid", "pswd"]

            for keyword in keywords:
                try:
                    if keyword in load.decode("utf-8"):
                        return True
                except:
                    break

            return False


close_sniffer = False


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
        global close_sniffer
        close_sniffer = True
        time.sleep(1)
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
        thread_sniff = threading.Thread(target=self.sniff, args=(None, None))
        self.sniff_thread = thread_sniff
        thread_sniff.start()

    def stop_filter(self, packet):
        global close_sniffer
    # return True to stop the sniffing process when a certain condition is met
        # print(close_sniffer)
        if close_sniffer:
            return True

    # this function is used for sniffing
    def sniff(self, interface, filters):
        scapy.sniff(iface=interface, store=False,
                    prn=self.process_sniffed_packets, filter=filters, stop_filter=self.stop_filter)

    def process_sniffed_packets(self, packet):
        # time.sleep(1)
        # print(packet)
        self.sub_window.add_information(packet)


if __name__ == '__main__':
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec()
