import json
import os
import threading
import time
from collections import deque, defaultdict, Counter

import joblib
from flask import Flask, render_template, jsonify
from scapy.all import sniff, get_if_list, conf

from feature_extraction import pkt_to_basic_features

#Paths & Config

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(BASE_DIR, "model_artifacts", "model.joblib")
FEATURES_PATH = os.path.join(BASE_DIR, "model_artifacts", "feature_columns.json")

DEFAULT_IFACE = os.environ.get(
    "NIDS_IFACE",
    r"\Device\NPF_{1601AAEB-8611-4579-9826-6EDB63D01BAC}" 
)

#ML model

model = None
FEATURE_COLS = None

if os.path.exists(MODEL_PATH) and os.path.exists(FEATURES_PATH):
    try:
        model = joblib.load(MODEL_PATH)
        with open(FEATURES_PATH, "r", encoding="utf-8") as f:
            FEATURE_COLS = json.load(f)
        print(f"[OK] ML model loaded ({len(FEATURE_COLS)} features)")
    except Exception as e:
        print("[WARN] Model load failed:", e)
else:
    print("[INFO] No model found → running in rule mode")

#Runtime storage

alerts = deque(maxlen=2000)

protocol_counts = Counter()
severity_counts = Counter()
alert_type_counts = Counter()

recent_src_dst = defaultdict(deque)

#Flask App

app = Flask(__name__, template_folder="templates", static_folder="static")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/alerts")
def get_alerts():
    return jsonify({
        "alerts": list(alerts),
        "count": len(alerts)
    })

@app.route("/stats")
def get_stats():
    return jsonify({
        "protocols": dict(protocol_counts),
        "severities": dict(severity_counts),
        "types": dict(alert_type_counts)
    })

@app.route("/clear", methods=["POST"])
def clear_alerts():
    alerts.clear()
    protocol_counts.clear()
    severity_counts.clear()
    alert_type_counts.clear()
    recent_src_dst.clear()
    return jsonify({"ok": True})

#Helpers

def build_feature_vector(basic_features):
    row = {c: 0 for c in FEATURE_COLS}
    for k, v in basic_features.items():
        if k in row:
            row[k] = v
    return [row[c] for c in FEATURE_COLS]

def classify_payload(payload):
    try:
        s = payload.decode("utf-8", errors="ignore").lower()
    except:
        return None

    if any(x in s for x in ("select ", "union ", "or 1=1", "drop table", "insert into")):
        return "SQLi"
    if any(x in s for x in ("login", "password", "username", "signin", "click here")):
        return "Phishing"
    return None

def severity_from_size(pkt_len):
    if pkt_len > 3000:
        return "high"
    if pkt_len > 900:
        return "medium"
    return "low"

def detect_ddos(src, dst):
    now = time.time()
    dq = recent_src_dst[(src, dst)]
    dq.append(now)

    while dq and now - dq[0] > 10:
        dq.popleft()

    return len(dq) > 40

#Packet Processor

def process_packet(pkt):
    try:

        print("PACKET:", pkt.summary())

        pkt_len = len(pkt)

        proto = "OTHER"
        if pkt.haslayer("TCP"):
            proto = "TCP"
        elif pkt.haslayer("UDP"):
            proto = "UDP"
        elif pkt.haslayer("ICMP"):
            proto = "ICMP"

        src = pkt.getlayer("IP").src if pkt.haslayer("IP") else "?"
        dst = pkt.getlayer("IP").dst if pkt.haslayer("IP") else "?"

        ts = time.strftime("%H:%M:%S")

        protocol_counts[proto] += 1

        payload = b""
        if pkt.haslayer("Raw"):
            payload = bytes(pkt["Raw"].load)

        alert_type = None
        severity = severity_from_size(pkt_len)

        # Payload heuristics
        payload_type = classify_payload(payload)
        if payload_type:
            alert_type = payload_type
            severity = "high" if payload_type == "SQLi" else "medium"
            alert_type_counts[payload_type] += 1

        # DDoS detection
        if detect_ddos(src, dst):
            alert_type = "DDoS"
            severity = "high"
            alert_type_counts["DDoS"] += 1

        # ML detection
        if model and FEATURE_COLS:
            features = pkt_to_basic_features(pkt)
            x = build_feature_vector(features)
            try:
                pred = model.predict([x])[0]
                if int(pred) == 1:
                    alert_type = "ML_ALERT"
                    alert_type_counts["ML_ALERT"] += 1
            except Exception as e:
                print("[ML ERROR]", e)

        # always create alert 
        alert = {
            "time": ts,
            "proto": proto,
            "src": src,
            "dst": dst,
            "type": alert_type or "Traffic",
            "severity": severity,
            "message": pkt.summary()
        }

        alerts.appendleft(alert)
        severity_counts[severity] += 1

    except Exception as e:
        print("[ERROR] process_packet:", e)

def scapy_capture_thread(iface):
    print("[OK] Sniffing on:", iface)
    try:
        sniff(
            iface=iface,
            prn=process_packet,
            store=False,
            L2socket=conf.L3socket
        )
    except Exception as e:
        print("[FATAL] Scapy sniff failed:", e)

def choose_iface():
    if DEFAULT_IFACE:
        return DEFAULT_IFACE
    for i in get_if_list():
        if "loopback" not in i.lower():
            return i
    return None

def start_capture():
    iface = choose_iface()
    if not iface:
        print("[ERROR] No interface found")
        return

    t = threading.Thread(
        target=scapy_capture_thread,
        args=(iface,),
        daemon=True
    )
    t.start()
    print("[OK] Sniffer thread started")

if __name__ == "__main__":
    print("[SYSTEM] NIDS starting...")
    start_capture()
    app.run(host="0.0.0.0", port=5000, debug=True)
