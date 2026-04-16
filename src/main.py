from parser import load_traffic_data
from detector import run_all_detections
import sys

print("Starting project...")

# get file path from command line OR default
if len(sys.argv) > 1:
    file_path = sys.argv[1]
else:
    file_path = "data/sample_traffic.csv"

df = load_traffic_data(file_path)

print("\nData loaded:")
print(df.head())

alerts = run_all_detections(df)

print("\n=== Alerts ===")
print(alerts)

alerts = alerts[["src_ip", "alert", "count", "severity", "risk_score"]]

alerts.to_csv("output/alerts.csv", index=False)
print("\nTop 5 High Risk Alerts:")
print(alerts.head())

print("\nDone. Alerts saved to output/alerts.csv")