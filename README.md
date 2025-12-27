# CodeAlpha_BasicNetworkSniffer
🖥️ Network Packet Sniffer Using Python & Scapy
📄 Technical Overview

This project implements a packet-level network traffic analysis tool using Python and the Scapy library to capture and inspect live network packets in real time. The sniffer operates by interfacing directly with the system’s network interface and performs inspection at the Network Layer (Layer 3) and Transport Layer (Layer 4) of the TCP/IP protocol stack.

Each captured packet is validated for the presence of an IP header, from which the tool extracts the source and destination IP addresses along with the IP protocol field, providing visibility into the underlying protocol used for communication. The application further analyzes transport-layer encapsulation by identifying TCP and UDP packets and extracting their respective source and destination port numbers, enabling service-level traffic analysis.

The packet processing is implemented using an event-driven callback function, allowing packets to be analyzed immediately upon capture. To maintain controlled execution and resource efficiency, the sniffer limits packet capture to a predefined number of packets. This project demonstrates core techniques used in network monitoring, traffic inspection, and cybersecurity analysis, forming a foundation for intrusion detection and network defense systems.

🛠️ Technologies & Libraries

Python 3

Scapy – packet capture, protocol dissection, and field extraction

⚙️ Core Functional Capabilities

Real-time interception of network traffic

Layer 3 IP packet inspection and validation

Extraction of source and destination IP addresses

Analysis of the IP protocol field for traffic classification

Layer 4 transport protocol identification (TCP / UDP)

Extraction of TCP and UDP source and destination port numbers

Controlled packet capture using a defined packet count limit

Event-driven packet analysis via callback functions

▶️ Execution Instructions

Due to raw socket access requirements, the program must be executed with administrator/root privileges:

sudo python sniffer.py

🎯 Learning Outcomes & Technical Skills Developed

Practical understanding of the TCP/IP networking model

Interpretation of IP and transport-layer protocol fields

Analysis of service-level communication through port numbers

Hands-on experience with packet sniffing and inspection tools

Foundational knowledge applicable to intrusion detection systems (IDS) and network traffic monitoring

⚠️ Ethical & Legal Considerations

This tool is intended solely for educational and authorized testing purposes. Packet sniffing on networks without explicit permission may violate privacy regulations and organizational security policies.

🚀 Internship Context

Cyber Security Internship — CodeAlpha
Task 1: Basic Network Sniffer
