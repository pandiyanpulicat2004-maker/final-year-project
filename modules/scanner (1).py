import psutil
import time
from collections import defaultdict
from datetime import datetime

SUSPICIOUS_PORTS = {4444, 1337, 9001}
BEACON_MIN = 50
BEACON_MAX = 70
PERSISTENT_TIME = 300

flow_tracker = defaultdict(list)
risk_score = 0
alerts = []

LOG_FILE = "logs/scan_log.txt"
REPORT_FILE = "logs/scan_report.txt"

def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now()}] {msg}\n")

def scan_network(duration=60):
    global risk_score, alerts
    log("=== Malware C2 Scan Started ===")

    start = time.time()
    while time.time() - start < duration:
        for conn in psutil.net_connections(kind='inet'):
            if conn.raddr:
                key = (conn.raddr.ip, conn.raddr.port)
                flow_tracker[key].append(time.time())

                # Suspicious Port Detection
                if conn.raddr.port in SUSPICIOUS_PORTS:
                    risk_score += 20
                    alerts.append(f"Suspicious port used: {conn.raddr.port}")

        time.sleep(2)

    detect_beaconing()
    generate_report()
    log("=== Scan Completed ===")

def detect_beaconing():
    global risk_score
    for key, times in flow_tracker.items():
        if len(times) > 3:
            intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
            avg = sum(intervals) / len(intervals)

            if BEACON_MIN < avg < BEACON_MAX:
                risk_score += 50
                alerts.append(f"Beaconing detected from {key[0]}")

def generate_report():
    with open(REPORT_FILE, "w") as f:
        f.write("===== C2 Detection Report =====\n")
        f.write(f"Risk Score: {risk_score}\n\n")

        if alerts:
            f.write("ALERTS:\n")
            for a in alerts:
                f.write(f"- {a}\n")
        else:
            f.write("No malware detected.\n")
