from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
import sys
import os


def protocol_name(pkt):
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    return "OTHER"


def extract_ports(pkt):
    src_port = None
    dst_port = None

    if pkt.haslayer(TCP):
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport

    return src_port, dst_port


def pcap_to_csv(input_pcap: str, output_csv: str) -> None:
    packets = rdpcap(input_pcap)
    rows = []

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        src_port, dst_port = extract_ports(pkt)

        rows.append({
            "timestamp": (pkt.time),
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "protocol": protocol_name(pkt),
            "src_port": src_port,
            "dst_port": dst_port,
            "packet_size": len(pkt)
        })

    df = pd.DataFrame(rows)

    if df.empty:
        print("No IP packets found in the PCAP.")
        return

    df["timestamp"] = pd.to_datetime(df["timestamp"].astype(float), unit="s")
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    df.to_csv(output_csv, index=False)

    print(f"Converted {len(df)} packets from {input_pcap} to {output_csv}")


if __name__ == "__main__":
 input_pcap = sys.argv[1] if len(sys.argv) > 1 else "data/sample.pcap"
 output_csv = sys.argv[2] if len(sys.argv) > 2 else "output/converted_from_pcap.csv"
pcap_to_csv(input_pcap, output_csv)