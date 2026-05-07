
from flask import Flask, render_template, jsonify, request
import numpy as np, pandas as pd, random, threading, time, warnings
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
warnings.filterwarnings("ignore")

app = Flask("Cyber Shield")

# ── TRAIN MODELS ON STARTUP ───────────────────────────────────────────────────
print("⏳ Training AI models... (~20 seconds)")
np.random.seed(42)

def make_samples(n, bs, br, la, rpm, dur, cpu, label, atype):
    return pd.DataFrame({
        "bytes_sent":       np.random.randint(*bs,  n),
        "bytes_received":   np.random.randint(*br,  n),
        "login_attempts":   np.random.randint(*la,  n),
        "requests_per_min": np.random.randint(*rpm, n),
        "duration":         np.random.uniform(*dur, n).round(3),
        "cpu_usage":        np.random.uniform(*cpu, n).round(1),
        "label": [label]*n, "attack_type": [atype]*n
    })

df = pd.concat([
    make_samples(700,(100,5000),(200,10000),(1,3),(5,50),(0.5,5),(5,40),"normal","Normal"),
    make_samples(80,(50,200),(50,200),(50,200),(200,1000),(0.01,0.1),(5,30),"attack","Brute Force"),
    make_samples(80,(50000,200000),(100,500),(1,2),(5000,20000),(0.001,0.05),(85,100),"attack","DDoS"),
    make_samples(80,(500000,5000000),(100,500),(1,2),(1,5),(30,300),(5,20),"attack","Data Exfiltration"),
    make_samples(80,(40,80),(0,40),(1,2),(500,2000),(0.001,0.01),(5,15),"attack","Port Scan"),
    make_samples(80,(200,1000),(100,800),(1,3),(10,100),(60,600),(10,30),"attack","Insider Threat"),
], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)

FEATURES = ["bytes_sent","bytes_received","login_attempts","requests_per_min","duration","cpu_usage"]
X = df[FEATURES].values
scaler = StandardScaler()
Xs = scaler.fit_transform(X)

iso = IsolationForest(n_estimators=100, contamination=0.35, random_state=42)
iso.fit(Xs)

rf = RandomForestClassifier(n_estimators=100, random_state=42)
rf.fit(Xs, df["attack_type"].values)

km = KMeans(n_clusters=6, random_state=42, n_init=10)
km.fit(Xs)

print("✅ Models ready!")

# ── CONSTANTS ────────────────────────────────────────────────────────────────
ATTACK_INFO = {
    "Normal":             {"icon":"✅","color":"#22c55e","severity":"None",     "risk":0,  "desc":"Regular authorized traffic with no suspicious indicators."},
    "Brute Force":        {"icon":"💥","color":"#f97316","severity":"High",     "risk":75, "desc":"Repeated login attempts trying to guess passwords by trial and error."},
    "DDoS":               {"icon":"🌊","color":"#ef4444","severity":"Critical", "risk":95, "desc":"Massive flood of traffic overwhelming the server to cause downtime."},
    "Data Exfiltration":  {"icon":"📤","color":"#a855f7","severity":"High",     "risk":85, "desc":"Unauthorized large-scale transfer of sensitive data out of the system."},
    "Port Scan":          {"icon":"🔍","color":"#3b82f6","severity":"Medium",   "risk":45, "desc":"Systematic probe of network ports to find vulnerabilities to exploit."},
    "Insider Threat":     {"icon":"🕵️","color":"#f59e0b","severity":"High",     "risk":80, "desc":"Malicious activity from within the organization — unusual data access patterns."},
}
ALGOS = {
    "Isolation Forest": "Unsupervised. Isolates anomalies by randomly partitioning data. Events that are easy to isolate = anomalies.",
    "Random Forest":    "Supervised. 100 decision trees vote on the attack type. Gives exact threat classification.",
    "K-Means":          "Clustering. Groups traffic into 6 behavioral clusters. Outlier clusters = suspicious behavior.",
}

# ── LIVE EVENT ENGINE ────────────────────────────────────────────────────────
events     = []
alerts_log = []
stats      = {"total":0,"attacks":0,"normal":0,
              "Brute Force":0,"DDoS":0,"Data Exfiltration":0,"Port Scan":0,"Insider Threat":0}

def rip(): return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

PRESETS = {
    "Normal":            [(100,5000),(200,10000),(1,3),(5,50),(0.5,5),(5,40)],
    "Brute Force":       [(50,200),(50,200),(50,200),(200,1000),(0.01,0.1),(5,30)],
    "DDoS":              [(50000,200000),(100,500),(1,2),(5000,20000),(0.001,0.05),(85,100)],
    "Data Exfiltration": [(500000,5000000),(100,500),(1,2),(1,5),(30,300),(5,20)],
    "Port Scan":         [(40,80),(0,40),(1,2),(500,2000),(0.001,0.01),(5,15)],
    "Insider Threat":    [(200,1000),(100,800),(1,3),(10,100),(60,600),(10,30)],
}

def predict(feat):
    fs = scaler.transform([feat])
    iso_r  = "Anomaly"  if iso.predict(fs)[0]==-1 else "Normal"
    rf_r   = rf.predict(fs)[0]
    km_r   = int(km.predict(fs)[0])
    conf   = round(float(rf.predict_proba(fs).max()*100),1)
    verdict= rf_r if rf_r!="Normal" else ("Brute Force" if iso_r=="Anomaly" else "Normal")
    return iso_r, rf_r, km_r, verdict, conf

def gen_event():
    kind = random.choices(list(PRESETS.keys()), weights=[55,10,10,10,8,7])[0]
    ranges = PRESETS[kind]
    feat = [
        random.randint(*ranges[0]), random.randint(*ranges[1]),
        random.randint(*ranges[2]), random.randint(*ranges[3]),
        round(random.uniform(*ranges[4]),3), round(random.uniform(*ranges[5]),1)
    ]
    iso_r, rf_r, km_r, verdict, conf = predict(feat)
    info = ATTACK_INFO.get(verdict, ATTACK_INFO["Normal"])
    ev = {
        "id": len(events)+1,
        "time": datetime.now().strftime("%H:%M:%S"),
        "date": datetime.now().strftime("%d %b %Y"),
        "src_ip": rip(), "dst_ip": f"10.0.{random.randint(0,5)}.{random.randint(1,50)}",
        "bytes_sent": feat[0], "bytes_received": feat[1],
        "login_attempts": feat[2], "requests_per_min": feat[3],
        "duration": feat[4], "cpu_usage": feat[5],
        "iso": iso_r, "rf": rf_r, "kmeans": f"Cluster {km_r}",
        "verdict": verdict, "severity": info["severity"],
        "risk": info["risk"], "color": info["color"],
        "icon": info["icon"], "is_attack": verdict!="Normal",
        "confidence": conf,
        "protocol": random.choice(["TCP","UDP","HTTP","HTTPS"]),
        "port": random.choice([80,443,22,8080,3306,21,25]),
    }
    events.append(ev)
    if len(events)>500: events.pop(0)
    stats["total"]+=1
    if verdict!="Normal":
        stats["attacks"]+=1
        if verdict in stats: stats[verdict]+=1
        if len(alerts_log)<200: alerts_log.insert(0,ev)
    else:
        stats["normal"]+=1

def bg():
    while True:
        gen_event()
        time.sleep(1.2)

threading.Thread(target=bg, daemon=True).start()

# ── ROUTES ───────────────────────────────────────────────────────────────────
@app.route("/")
def home(): return render_template("home.html", attack_info=ATTACK_INFO)

@app.route("/dashboard")
def dashboard(): return render_template("dashboard.html")

@app.route("/threats")
def threats(): return render_template("threats.html", attack_info=ATTACK_INFO)

@app.route("/scanner")
def scanner(): return render_template("scanner.html")

@app.route("/alerts")
def alerts(): return render_template("alerts.html")

@app.route("/about")
def about(): return render_template("about.html", algos=ALGOS, attack_info=ATTACK_INFO)

# ── API ───────────────────────────────────────────────────────────────────────
@app.route("/api/stats")
def api_stats():
    t=max(stats["total"],1)
    return jsonify({**stats,"pct":round(stats["attacks"]/t*100,1)})

@app.route("/api/events")
def api_events():
    f = request.args.get("filter","all")
    limit = int(request.args.get("limit",60))
    evs = events[-200:][::-1]
    if f!="all": evs=[e for e in evs if e["verdict"]==f]
    return jsonify(evs[:limit])

@app.route("/api/alerts")
def api_alerts():
    return jsonify(alerts_log[:50])

@app.route("/api/timeline")
def api_timeline():
    last=events[-40:]
    return jsonify([{"time":e["time"],"reqs":e["requests_per_min"],
                     "risk":e["risk"],"verdict":e["verdict"]} for e in last])

@app.route("/api/scan", methods=["POST"])
def api_scan():
    d=request.json
    feat=[float(d.get(k,0)) for k in ["bytes_sent","bytes_received","login_attempts",
                                        "requests_per_min","duration","cpu_usage"]]
    iso_r,rf_r,km_r,verdict,conf=predict(feat)
    info=ATTACK_INFO.get(verdict,ATTACK_INFO["Normal"])
    return jsonify({"iso":iso_r,"rf":rf_r,"kmeans":f"Cluster {km_r}",
                    "verdict":verdict,"severity":info["severity"],
                    "risk":info["risk"],"color":info["color"],
                    "icon":info["icon"],"confidence":conf,"desc":info["desc"]})

@app.route("/api/threat_detail/<name>")
def threat_detail(name):
    info=ATTACK_INFO.get(name,{})
    evs=[e for e in events if e["verdict"]==name][-20:][::-1]
    return jsonify({"info":info,"recent":evs,"count":stats.get(name,0)})

if __name__=="__main__":
    app.run(debug=False, port=5000)
