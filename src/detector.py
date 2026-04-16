import pandas as pd

# -------------------------------
# Detect Port Scanning
# Idea: If one source IP is contacting many different destination IPs,it might be scanning the network
# -------------------------------
def detect_port_scan(df):

    # count how many unique destination IPs each source IP is hitting
    grouped = df.groupby("src_ip")["dst_ip"].nunique().reset_index()

    # if it connects to 5 or more different IPs → suspicious
    scans = grouped[grouped["dst_ip"] >= 5].copy()

    # add useful columns
    scans["alert"] = "Port Scan"
    scans["count"] = scans["dst_ip"]   # number of targets
    scans["severity"] = "High"

    # return only important columns
    return scans[["src_ip", "alert", "count", "severity"]]


# -------------------------------
# Detect DNS spikes
# Idea: Too many DNS requests in short time = possible anomaly
# -------------------------------
def detect_dns_spike(df):

    # filter only DNS traffic (port 53)
    dns = df[df["dst_port"] == 53]

    # count requests per source IP
    grouped = dns.groupby("src_ip").size().reset_index(name="count")

    # threshold: 8 or more requests
    spikes = grouped[grouped["count"] >= 8].copy()

    spikes["alert"] = "DNS Spike"
    spikes["severity"] = "Medium"

    return spikes[["src_ip", "alert", "count", "severity"]]


# -------------------------------
# Detect Brute Force (SSH)
# Idea: Repeated attempts to same machine on port 22
# -------------------------------
def detect_brute_force(df):

    # filter SSH traffic
    ssh = df[df["dst_port"] == 22]

    # count how many times same src → same dst
    grouped = ssh.groupby(["src_ip", "dst_ip"]).size().reset_index(name="count")

    # if repeated many times → brute force
    brute = grouped[grouped["count"] >= 5].copy()

    brute["alert"] = "Brute Force Attempt"
    brute["severity"] = "High"

    return brute[["src_ip", "alert", "count", "severity"]]


# -------------------------------
# Detect Suspicious Ports
# Idea:Ports like 4444, 5555, 6666 are often used in malware/backdoors
# -------------------------------
def detect_suspicious_ports(df):

    suspicious_ports = [4444, 5555, 6666]

    # filter those ports
    sus = df[df["dst_port"].isin(suspicious_ports)]

    # count occurrences per source
    grouped = sus.groupby("src_ip").size().reset_index(name="count")

    grouped["alert"] = "Suspicious Port Activity"
    grouped["severity"] = "High"

    return grouped[["src_ip", "alert", "count", "severity"]]


# -------------------------------
# Detect Large Packets
# Idea: unusually large packets might indicate abnormal transfer
# -------------------------------
def detect_large_packets(df):

    large = df[df["packet_size"] > 700]

    grouped = large.groupby("src_ip").size().reset_index(name="count")

    grouped["alert"] = "Large Packet Anomaly"
    grouped["severity"] = "Low"

    return grouped[["src_ip", "alert", "count", "severity"]]


# -------------------------------
# Combine all detections
# -------------------------------
def run_all_detections(df):

    results = []

    results.append(detect_port_scan(df))
    results.append(detect_dns_spike(df))
    results.append(detect_brute_force(df))
    results.append(detect_suspicious_ports(df))
    results.append(detect_large_packets(df))

    final = pd.concat(results, ignore_index=True)

    final = final.drop_duplicates()

    #  NEW
    final = add_risk_score(final)

    #  NEW
    final = final.sort_values(by="risk_score", ascending=False)

    return final

# -------------------------------
# Assign risk score based on severity + behavior
# -------------------------------
def add_risk_score(df):

    def calculate_score(row):

        # base score from severity
        if row["severity"] == "High":
            base = 70
        elif row["severity"] == "Medium":
            base = 50
        else:
            base = 30

        # increase score based on activity count
        # (safe check if count exists)
        count = row["count"] if "count" in row else 1

        extra = min(count * 2, 30)

        return base + extra

    df["risk_score"] = df.apply(calculate_score, axis=1)

    return df