# **Intrusion Detection System (IDS) for Network Security**  
🚀 **A real-time Intrusion Detection System (IDS) that detects cyber threats using packet sniffing and machine learning.**

## **🔍 Overview**  
This **Intrusion Detection System (IDS)** monitors network traffic in real time to detect potential security threats. It leverages **packet sniffing** with `Scapy`, **machine learning-based malicious URL detection**, and an **interactive GUI** built with `PySide6`. The system can identify and alert users to various cyber threats, such as:  
✅ **SQL Injection**  
✅ **Cross-Site Scripting (XSS)**  
✅ **XXE Attacks**  
✅ **Command Injection**  
✅ **Malicious URLs & IPs**  
✅ **Credential Harvesting**  

---

## **🛠️ Features**  
✔️ **Live Packet Sniffing** – Captures and analyzes network packets in real time.  
✔️ **Machine Learning-based URL Detection** – Identifies phishing and malicious links.  
✔️ **GUI Interface** – Displays detected threats with real-time alerts.  
✔️ **Custom Rule-Based Detection** – Detects common injection attacks.  
✔️ **IP & URL Reputation Check** – Matches network traffic against known malicious sources.  

---

## **🖥️ Technologies Used**  
- **Programming Language:** Python  
- **Packet Sniffing:** `Scapy`  
- **Machine Learning:** `TF-IDF`, `Logistic Regression`, `Sklearn`, `Joblib`  
- **GUI Framework:** `PySide6`  
- **Networking:** `HTTP`, `TCP`, `DNS`, `ARP`, `ICMP`  

---

## **⚡ Installation Guide**  

### **1️⃣ Clone the Repository**  
```bash
git clone https://github.com/yourusername/Intrusion-Detection-System.git
cd Intrusion-Detection-System
```

### **2️⃣ Install Dependencies**  
```bash
pip install -r requirements.txt
```

### **3️⃣ Run the IDS**  
```bash
python main.py
```

---

## **📌 How It Works**  
1️⃣ **Live Packet Capture:** Uses `Scapy` to capture network packets and extract data.  
2️⃣ **Threat Detection:**  
   - **Rule-based detection** for common attack patterns.  
   - **Machine learning model** to classify URLs as safe or malicious.  
3️⃣ **Real-time Alerts:** Displays warnings for detected threats.  

---

## **🖼️ Screenshots & Demo (Optional)**  
![IMU IDS](https://github.com/user-attachments/assets/8f0834dd-e266-47ec-adc5-3045a14dd609)
![Network Sniffer](https://github.com/user-attachments/assets/3183d6a0-a308-4779-9bff-d3f1af576292)


---

## **🚀 Future Enhancements**  
🔹 **Integrate AI-based anomaly detection**  
🔹 **Expand database of known malicious URLs/IPs**  
🔹 **Enhance GUI for more detailed reports**  

---

## **📜 License**  
This project is licensed under the **MIT License**. Feel free to use and contribute.  
