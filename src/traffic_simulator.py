import pandas as pd
import random
from datetime import datetime, timedelta

rows = []

# random start date between April 10–20
base_date = datetime(2026, 4, random.randint(10, 20), random.randint(0, 23), random.randint(0, 59), 0)

# helper function to generate random IP
def random_ip():
    return f"192.168.1.{random.randint(2, 254)}"

# helper function to generate random external IP
def external_ip():
    return f"{random.randint(20, 200)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"


# 🔹 NORMAL TRAFFIC
for i in range(30):
    rows.append({
        "timestamp": base_date + timedelta(seconds=random.randint(1, 500)),
        "src_ip": random_ip(),
        "dst_ip": random.choice(["8.8.8.8", "8.8.4.4", "1.1.1.1"]),
        "protocol": "DNS",
        "src_port": random.randint(50000, 65000),
        "dst_port": 53,
        "packet_size": random.randint(60, 120)
    })


# 🔹 HTTP TRAFFIC
for i in range(25):
    rows.append({
        "timestamp": base_date + timedelta(seconds=random.randint(500, 1000)),
        "src_ip": random_ip(),
        "dst_ip": "192.168.1.1",
        "protocol": "HTTP",
        "src_port": random.randint(50000, 65000),
        "dst_port": 80,
        "packet_size": random.randint(200, 600)
    })


# 🔹 PORT SCAN
scanner_ip = random_ip()
for i in range(random.randint(6, 10)):
    rows.append({
        "timestamp": base_date + timedelta(seconds=1000 + i),
        "src_ip": scanner_ip,
        "dst_ip": random_ip(),
        "protocol": "TCP",
        "src_port": random.randint(40000, 50000),
        "dst_port": 22,
        "packet_size": random.randint(90, 150)
    })


# 🔹 DNS SPIKE
dns_attacker = random_ip()
for i in range(random.randint(8, 15)):
    rows.append({
        "timestamp": base_date + timedelta(seconds=1200 + i),
        "src_ip": dns_attacker,
        "dst_ip": random.choice(["8.8.8.8", "1.1.1.1"]),
        "protocol": "DNS",
        "src_port": random.randint(52000, 65000),
        "dst_port": 53,
        "packet_size": random.randint(70, 110)
    })


# 🔹 SUSPICIOUS PORT ACTIVITY
for i in range(5):
    rows.append({
        "timestamp": base_date + timedelta(seconds=1500 + i),
        "src_ip": random_ip(),
        "dst_ip": external_ip(),
        "protocol": "TCP",
        "src_port": random.randint(50000, 65000),
        "dst_port": random.choice([4444, 5555, 6666]),
        "packet_size": random.randint(650, 900)
    })


# 🔹 BRUTE FORCE
attacker = random_ip()
victim = random_ip()

for i in range(random.randint(5, 8)):
    rows.append({
        "timestamp": base_date + timedelta(seconds=1800 + i),
        "src_ip": attacker,
        "dst_ip": victim,
        "protocol": "TCP",
        "src_port": random.randint(60000, 65000),
        "dst_port": 22,
        "packet_size": random.randint(80, 120)
    })


# convert to dataframe
df = pd.DataFrame(rows)

# shuffle rows (VERY IMPORTANT — makes it realistic)
df = df.sample(frac=1).reset_index(drop=True)

# save file
df.to_csv("data/mixed_traffic.csv", index=False)

print("✅ Random realistic dataset generated: data/mixed_traffic.csv")