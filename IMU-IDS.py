from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QTextEdit
from PySide6.QtWidgets import QScrollArea
from PySide6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QDialog
import sys
import threading
from scapy.layers.inet import IP
import scapy.all as scapy
from argparse import RawTextHelpFormatter
import argparse
from scapy.layers import http, inet, dhcp, dns, tls
from scapy.layers.l2 import Ether
import time
import joblib
import pandas as pd
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether, Dot3
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP
from scapy.packet import Raw
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
# from url_ml import predict_for_me

Live_Ids_String = "Live IDS"
Pre_Build_String = "Pre Build IDS"
ML_Based_String = "ML based"


# making tokens for url
def makeTokens(f):
    # make tokens after splitting by slash
    tkns_BySlash = str(f.encode('utf-8')).split('/')
    total_Tokens = []

    for i in tkns_BySlash:
        tokens = str(i).split('-')  # make tokens after splitting by dash
        tkns_ByDot = []

    for j in range(0, len(tokens)):
        # make tokens after splitting by dot
        temp_Tokens = str(tokens[j]).split('.')
        tkns_ByDot = tkns_ByDot + temp_Tokens
        total_Tokens = total_Tokens + tokens + tkns_ByDot
        total_Tokens = list(set(total_Tokens))  # remove redundant tokens

        if 'com' in total_Tokens:
            # removing .com since it occurs a lot of times and it should not be included in our features
            total_Tokens.remove('com')

    return total_Tokens

urls_data = pd.read_csv("./ml_ids/mail_url_dataset.csv")
vectorizer = TfidfVectorizer(tokenizer=makeTokens)

url_list = urls_data["url"]
y =  urls_data["label"]
Xx = vectorizer.fit_transform(url_list)


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

        self.text_edit.setStyleSheet('''
            QLabel {
                font-weight: bold;
                color: black;
                text-align: center;
                font-size: 20px;
                padding: 20px;
            }
        ''')

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(self.text_edit)
        layout = QVBoxLayout()
        layout.addWidget(scroll_area)
        self.setLayout(layout)

    # geting the URL
    def get_url(self, packet):
        if packet.haslayer('HTTPRequest'):
            http_layer = packet.getlayer('HTTPRequest')
            url = http_layer.Host.decode() + http_layer.Path.decode()
            return url

        return None

 
    # checking url is malicious or not
    def malicous_url(self, url):
        check_url = vectorizer.transform([url])

        model = joblib.load('./ml_ids/model.pkl')
        predict = model.predict(check_url)

        print(predict)
        if predict == 'bad':
            return True
      
        return False

    # adding information to screen
    def add_information(self, packet):
        alert_flag = False
        alert = ''

        # Append information to the text edit widget
        if self.args == ML_Based_String:
            url = self.get_url(packet)

            if url != None:
                if self.malicous_url(url):
                    alert_flag = True
                    alert = '[+] Possible Suspicious URL [+]\n'
                else:
                    alert_flag = True
                    alert = '[+] Possible Safe URL [+]\n'


            print("Ml based")
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

                if self.live_is_malicious_url(packet):
                    alert_flag = True
                    alert += '[+] Connecting to Malicious Site [+]\n'

            print("This is LIVE IDS")

        # if alert generated print that
        if alert_flag:
            self.text_edit.setText(self.text_edit.text(
            ) + "\n -------------------------------------------------------------------------------- \n")
            self.text_edit.setText(self.text_edit.text() + "\n" + (alert))
            self.text_edit.setText(
                self.text_edit.text() + "\n" + (packet.summary()))
            self.text_edit.setText(
                self.text_edit.text() + "\nURL : " + self.get_url(packet))
            self.text_edit.setText(self.text_edit.text(
            ) + "\n\n -------------------------------------------------------------------------------- \n")

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
    # --------------------------------------------------
    # --------------- Malicious IP Address -------------
    # --------------------------------------------------

    def live_is_malicious_url(self, packet):
        if packet.haslayer(IP):
            # extract source and destination IP addresses
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            # do something with the IP addresses
            # print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")

            with open("malicious_ip.txt", "r") as file:
                # Loop over each line in the file
                for line in file:
                    # Remove whitespace from the beginning and end of the line
                    line = line.strip()
                    # Compare the line with a string
                    if line == dst_ip:
                        # print("Match found: ", line)
                        return True
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

        # # Create button
        # button1 = QPushButton("Pre Build Intrusion Detection")
        # button1.clicked.connect(self.pre_build)
        # main_layout.addWidget(button1)

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
        print("Live Intrusion Detection")
        self.sub_window = SubWindow(Live_Ids_String)
        self.start_sub_window()

    def pre_build(self):
        print("Pre Build Intrusion Detection")
        self.sub_window = SubWindow(Pre_Build_String)
        self.start_sub_window()

    def ml_based_ids(self):
        print("ML Based Intrusion Detection")
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
