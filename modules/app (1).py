from flask import Flask, render_template, jsonify
import threading
import os
from scanner import scan_network

app = Flask(__name__)

LOG_FILE = "logs/scan_log.txt"
REPORT_FILE = "logs/scan_report.txt"

def read_file(path):
    if not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

def clear_file(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("")

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/how-it-works")
def how_it_works():
    return render_template("how_it_works.html")

@app.route("/start_scan")
def start_scan():
    clear_file(LOG_FILE)
    clear_file(REPORT_FILE)
    threading.Thread(target=scan_network, daemon=True).start()
    return "Scan Started"

@app.route("/get_logs")
def get_logs():
    return jsonify({"logs": read_file(LOG_FILE)})

@app.route("/get_report")
def get_report():
    return jsonify({"report": read_file(REPORT_FILE)})

if __name__ == "__main__":
    app.run(debug=True)
