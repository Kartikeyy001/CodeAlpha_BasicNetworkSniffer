from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_analyzer(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "OTHER"

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"

        print("\n==============================")
        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")
        print(f"Protocol       : {protocol}")

        if packet.haslayer(TCP) and packet[TCP].payload:
            print(f"Payload        : {bytes(packet[TCP].payload)}")

print("Starting Network Sniffer...")
sniff(prn=packet_analyzer, store=False)

