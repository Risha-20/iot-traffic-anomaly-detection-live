## Architecture

1. Traffic Generator - Simulates IoT network behavior  
2. Attack Injector - Injects anomalies (port scan, brute force)  
3. Detection Engine - Applies rule-based detection  
4. Risk Scoring - Assigns severity-based scores  
5. Output - Real-time alerts + CSV logging  

## Detection Logic

- Port Scan - High number of unique destinations  
- Brute Force - Repeated SSH attempts  
- DNS Spike - Excessive DNS requests  
- Suspicious Ports - Known malicious ports (4444, 5555, 6666)  
- Large Packets - Unusual payload sizes  

## Future Improvements

- Machine Learning integration  
- Live packet capture (Wireshark/Scapy streaming)  
- Dashboard (Splunk / ELK / Streamlit)
