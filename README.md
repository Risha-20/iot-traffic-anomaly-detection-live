# Real-Time IoT Traffic Anomaly Detection System

## Overview
For a long time, I was working with static datasets to detect cyber attacks.  
But real-world systems don’t work that way — they detect threats as they happen.

So I built a real-time IoT traffic simulation and anomaly detection pipeline that identifies attacks live as traffic flows.

This project simulates how SOC teams monitor, detect, and respond to threats in real time.

---

## Architecture

Traffic Generator → Attack Injector → Detection Engine → Risk Scoring → Alert System

---

## Features

- Real-time traffic simulation (multi-day network activity)
- Attack injection:
  - Port Scan
  - Brute Force
  - DNS Spike
- Streaming anomaly detection engine
- Risk scoring system based on behavior patterns
- Live alert generation (SIEM-style console output)
- Aggregated alert tracking

---

## Sample Dataset

The system generates realistic multi-day traffic:

- April 13–17 simulated network data
- Protocols: TCP, HTTP, DNS
- Includes normal + malicious traffic patterns

---

## Live Detection in Action

### Dataset (Multi-Day Traffic)
![Dataset](screenshots/01_dataset_multi_day_traffic.png)

### DNS Spike Detection
![DNS Spike](screenshots/03_live_detection_dns_spike.png)

### Port Scan & Brute Force Detection
![Attacks](screenshots/04_live_detection_portscan_bruteforce.png)

### Live Attack Stream
![Live Stream](screenshots/05_live_attack_status_stream.png)

---

## How It Works

1. Traffic Generator simulates realistic IoT network traffic  
2. Attack Injector introduces malicious behaviors  
3. Detection Engine analyzes packets in real time  
4. Risk Scoring assigns severity based on patterns  
5. Alerts are generated instantly for suspicious activity  

---

## How to Run

```bash
python src/traffic_simulator.py
python src/live_stream.py
