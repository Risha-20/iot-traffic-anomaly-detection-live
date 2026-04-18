import csv
import random
from datetime import datetime, timedelta

# CONFIG
NUM_ROWS = 5000   # increase to 10000+ if needed
START_DATE = datetime(2026, 4, 13)
DAYS = 5  # 13 → 17

protocols = ["TCP", "DNS", "HTTP"]
ips = [f"192.168.1.{i}" for i in range(1, 255)]

def random_timestamp():
    day_offset = random.randint(0, DAYS - 1)
    base_date = START_DATE + timedelta(days=day_offset)

    random_time = timedelta(
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59)
    )

    return (base_date + random_time).strftime("%Y-%m-%d %H:%M:%S")

def generate_row():
    protocol = random.choice(protocols)

    src_ip = random.choice(ips)
    dst_ip = random.choice(ips)

    if protocol == "DNS":
        src_port = random.randint(1024, 65535)
        dst_port = 53
    elif protocol == "HTTP":
        src_port = random.randint(1024, 65535)
        dst_port = 80
    else:
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([22, 80, 443, 8080])

    packet_size = random.randint(40, 1500)

    return [
        random_timestamp(),
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        packet_size
    ]

# WRITE CSV
with open("data/mixed_traffic.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "timestamp", "src_ip", "dst_ip",
        "protocol", "src_port", "dst_port", "packet_size"
    ])

    for _ in range(NUM_ROWS):
        writer.writerow(generate_row())

print("Dataset generated successfully.")t