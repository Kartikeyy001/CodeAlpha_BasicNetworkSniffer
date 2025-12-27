# CodeAlpha_BasicNetworkSniffer
🖥️ Basic Network Sniffer Using Python & Scapy
📄 Technical Project Overview
This project implements a low-level network packet sniffer using Python and the Scapy library to capture and analyze live network traffic in real time. The application operates by interfacing directly with the network interface to intercept packets and performs Layer 3 (Network Layer) and Layer 4 (Transport Layer) inspection in accordance with the TCP/IP networking model.

Each captured packet is examined to verify the presence of an IP header, from which the source and destination IP addresses are extracted. The sniffer then identifies the encapsulated transport-layer protocol by analyzing packet layers, supporting TCP, UDP, and ICMP protocol detection. For TCP traffic, the program further inspects the packet payload and outputs raw payload bytes when present, enabling visibility into transmitted data segments.

The sniffer processes packets in real time using a callback-based analysis function and avoids packet persistence to optimize memory usage. This project provides foundational exposure to packet structure, protocol encapsulation, network traffic behavior, and traffic analysis techniques commonly used in cybersecurity monitoring and intrusion detection systems.

🛠️ Technologies & Libraries

Python 3
Scapy – packet sniffing, protocol parsing, and payload extraction

⚙️ Core Functional Capabilities

Real-time network traffic interception
Layer 3 IP packet validation and analysis
Transport-layer protocol classification TCP / UDP / ICMP)
Extraction and display of source and destination IP addresses
TCP payload inspection and raw data output
Event-driven packet processing using callback functions
Memory-efficient sniffing using non-persistent packet storage

▶️ Execution Instructions

Due to the requirement for raw socket access, the program must be executed with administrator/root privileges:
sudo python sniffer.py

🎯 Learning Outcomes & Skills Developed

Practical understanding of TCP/IP protocol stack
Packet-level network traffic analysis
Identification of transport-layer protocols
Interpretation of packet payload data
Familiarity with network monitoring and sniffing tools
Foundation for building intrusion detection and traffic analysis systems

⚠️ Ethical & Legal Considerations

This tool is intended strictly for educational purposes and must only be used on networks where explicit permission has been granted. Unauthorized packet sniffing may violate privacy laws and organizational security policies.

🚀 Internship Context

Cyber Security Internship — CodeAlpha
Task 1: Basic Network Sniffer
