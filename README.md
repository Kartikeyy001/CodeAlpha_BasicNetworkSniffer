# CodeAlpha_BasicNetworkSniffer
📌 Basic Network Sniffer
📖 Technical Description

This project implements a packet-level network sniffer using Python and the Scapy framework to capture and analyze live network traffic. The application operates at the network and transport layers of the TCP/IP model, inspecting packets in real time to extract critical metadata and payload information.

Each captured packet is analyzed to identify the IP layer, determine the transport-layer protocol (TCP, UDP, or ICMP), and extract source and destination IP addresses. For TCP packets, the program additionally inspects and displays the payload data, enabling low-level visibility into transmitted information.

This sniffer provides hands-on exposure to packet structure, protocol headers, and network communication behavior, which are foundational concepts in network security monitoring and traffic analysis.

🛠 Technologies Used

Python 3

Scapy (packet manipulation and sniffing library)

⚙️ Core Functionality

Real-time packet capture from network interfaces

Layer-3 (IP) packet inspection

Layer-4 protocol identification (TCP / UDP / ICMP)

Extraction of source and destination IP addresses

Payload inspection for TCP traffic

Memory-efficient sniffing using non-persistent packet storage

▶️ Execution Instructions

The program must be executed with elevated privileges to access raw network traffic:

sudo python sniffer.py

🎯 Learning Outcomes

Understanding of TCP/IP packet architecture

Practical experience with network traffic analysis

Familiarity with transport-layer protocols

Insight into payload data inspection and limitations

Foundation for intrusion detection and network monitoring systems

🚀 Internship Task

Cyber Security Internship — CodeAlpha
Task 1: Basic Network Sniffer
