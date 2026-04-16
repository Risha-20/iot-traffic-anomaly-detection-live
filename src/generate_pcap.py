from scapy.all import IP, TCP, UDP, DNS, DNSQR, wrpcap
import random

packets = []

# DNS traffic
for i in range(10):
    pkt = IP(
        src=f"192.168.1.{random.randint(2,100)}",
        dst="8.8.8.8"
    ) / UDP(
        sport=random.randint(50000,60000),
        dport=53
    ) / DNS(rd=1, qd=DNSQR(qname="google.com"))

    packets.append(pkt)

# HTTP traffic
for i in range(10):
    pkt = IP(
        src=f"192.168.1.{random.randint(2,100)}",
        dst="192.168.1.1"
    ) / TCP(
        sport=random.randint(50000,60000),
        dport=80
    )

    packets.append(pkt)

# Suspicious traffic (port 4444)
for i in range(5):
    pkt = IP(
        src=f"192.168.1.{random.randint(2,100)}",
        dst="45.33.32.156"
    ) / TCP(
        sport=random.randint(50000,60000),
        dport=4444
    )

    packets.append(pkt)

# Save PCAP file
wrpcap("data/sample.pcap", packets)

print("✅ sample.pcap generated inside data/")