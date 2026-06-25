# Advanced Network Sniffer using Python & Scapy

## Overview

This project is a Python-based Network Sniffer developed using the Scapy library. The tool captures live network packets, analyzes network traffic, extracts useful packet information, and stores the captured data for further analysis.

The project was developed as part of a Cybersecurity Internship Task to understand packet structures, network protocols, and how data flows across computer networks.

---

## Features

* Live packet capture using Scapy
* Source IP and Destination IP extraction
* Protocol identification

  * TCP
  * UDP
  * ICMP
  * DNS
  * HTTPS
* Source and Destination Port detection
* Payload extraction and inspection
* Automatic packet logging to CSV
* Suspicious port monitoring and alert generation
* Network traffic summary report
* Automatic capture termination after specified packet count

---

## Technologies Used

* Python 3
* Scapy
* Npcap (Windows Packet Capture Driver)

---

## Project Structure

```text
Network_Sniffer/
│
├── network_sniffer.py
├── packet_logs.csv
├── alerts.log
├── README.md
```

---

## Installation

### Step 1: Clone Repository

```bash
git clone <repository-url>
cd Network_Sniffer
```

### Step 2: Install Dependencies

```bash
pip install scapy
```

### Step 3: Install Npcap

Download and install Npcap:

https://npcap.com/

During installation, enable:

* Install Npcap in WinPcap API-compatible Mode

---

## Running the Program

Run PowerShell or Command Prompt as Administrator.

```bash
python network_sniffer.py
```

Example:

```text
ADVANCED NETWORK SNIFFER
Capturing 100 packets...
```

---

## Sample Output

```text
Packet # : 1
Time     : 2026-06-25 11:28:07
Source IP: 40.104.68.50
Dest IP  : 192.168.0.106
Protocol : HTTPS
Src Port : 443
Dst Port : 53118
```

---

## Packet Information Captured

The sniffer extracts:

* Timestamp
* Source IP Address
* Destination IP Address
* Protocol Type
* Source Port
* Destination Port
* Payload Information

---

## CSV Logging

All captured packets are automatically stored in:

```text
packet_logs.csv
```

Example:

```csv
Timestamp,Source_IP,Destination_IP,Protocol,Source_Port,Destination_Port
2026-06-25 11:28:07,40.104.68.50,192.168.0.106,HTTPS,443,53118
```

---

## Alert Generation

The system monitors suspicious ports such as:

```python
[21, 23, 445, 3389]
```

Alerts are stored in:

```text
alerts.log
```

---

## Traffic Summary Report

After capture completion, a summary report is generated.

Example:

```text
CAPTURE SUMMARY

Total Packets : 100
TCP Packets   : 98
UDP Packets   : 0
ICMP Packets  : 0
DNS Packets   : 2
HTTP Packets  : 0
HTTPS Packets : 95
```

---

## Learning Outcomes

Through this project, the following concepts were explored:

* Packet Sniffing
* Network Monitoring
* TCP/IP Protocol Suite
* DNS Communication
* HTTPS Traffic Analysis
* Network Traffic Logging
* Cybersecurity Monitoring Basics
* Packet Analysis using Scapy

---

## Limitations

* HTTPS payloads are encrypted and cannot be directly read.
* Deep packet inspection is not implemented.
* Works on local network interfaces only.

---

## Future Enhancements

* Real-time Dashboard
* PCAP File Export
* GeoIP Lookup
* Threat Intelligence Integration
* Advanced Intrusion Detection Rules
* Web-based Monitoring Interface

---

## Author

Saurabh Mudras

Cybersecurity Enthusiast | B.Tech CSE Student

---

## Disclaimer

This tool is intended for educational and authorized network monitoring purposes only. Do not use it on networks without proper permission.
