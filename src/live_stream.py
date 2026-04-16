import pandas as pd
import random
import time
from datetime import datetime
from detector import run_all_detections

# attack state variables
attack_mode = None
attack_counter = 0
attacker_ip = None
target_ip = None


def generate_row():
    global attack_mode, attack_counter, attacker_ip, target_ip

    # randomly trigger attack
    if attack_mode is None and random.random() < 0.1:
        attack_mode = random.choice(["port_scan", "brute_force", "dns_spike"])
        attack_counter = 0
        attacker_ip = f"192.168.1.{random.randint(50, 200)}"
        target_ip = f"192.168.1.{random.randint(1, 50)}"

        print(f"\n ATTACK STARTED: {attack_mode.upper()} from {attacker_ip}")

    # PORT SCAN
    if attack_mode == "port_scan":
        attack_counter += 1
        row = {
            "timestamp": datetime.now(),
            "src_ip": attacker_ip,
            "dst_ip": f"192.168.1.{random.randint(1, 255)}",
            "protocol": "TCP",
            "src_port": random.randint(40000, 65000),
            "dst_port": 22,
            "packet_size": random.randint(60, 120)
        }
        if attack_counter > 10:
            attack_mode = None
        return row

    # BRUTE FORCE
    if attack_mode == "brute_force":
        attack_counter += 1
        row = {
            "timestamp": datetime.now(),
            "src_ip": attacker_ip,
            "dst_ip": target_ip,
            "protocol": "TCP",
            "src_port": random.randint(40000, 65000),
            "dst_port": 22,
            "packet_size": random.randint(60, 120)
        }
        if attack_counter > 8:
            attack_mode = None
        return row

    # DNS SPIKE
    if attack_mode == "dns_spike":
        attack_counter += 1
        row = {
            "timestamp": datetime.now(),
            "src_ip": attacker_ip,
            "dst_ip": random.choice(["8.8.8.8", "1.1.1.1"]),
            "protocol": "DNS",
            "src_port": random.randint(50000, 65000),
            "dst_port": 53,
            "packet_size": random.randint(60, 100)
        }
        if attack_counter > 12:
            attack_mode = None
        return row

    # NORMAL TRAFFIC
    src_ip = f"192.168.1.{random.randint(1, 255)}"

    if random.random() < 0.5:
        dst_ip = f"192.168.1.{random.randint(1, 255)}"
    else:
        dst_ip = random.choice(["8.8.8.8", "1.1.1.1"])

    protocol = random.choice(["TCP", "DNS"])

    if protocol == "DNS":
        return {
            "timestamp": datetime.now(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": "DNS",
            "src_port": random.randint(50000, 65000),
            "dst_port": 53,
            "packet_size": random.randint(60, 120)
        }

    else:
        return {
            "timestamp": datetime.now(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": "TCP",
            "src_port": random.randint(40000, 65000),
            "dst_port": random.choice([80, 443, 4444, 5555, 6666]),
            "packet_size": random.randint(60, 900)
        }


def live_monitor():
    print(" Live Traffic Monitoring Started...\n")

    data = []
    seen_alerts = set()

    while True:
        row = generate_row()
        data.append(row)

        if len(data) > 30:
            data.pop(0)

        df = pd.DataFrame(data)

        print(f"New Packet: {row['src_ip']} → {row['dst_ip']} ({row['protocol']})")

        alerts = run_all_detections(df)
        seen_alerts = set()
        if not alerts.empty:
            print("\n ALERTS DETECTED:")
            print(alerts.head())

        time.sleep(1)


if __name__ == "__main__":
    live_monitor()