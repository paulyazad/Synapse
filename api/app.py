"""
Synapse — Flask API v2
======================
Fixed: embeds StackedTfidfEncoder, TwoStagePriorityClassifier, and
MultiLabelMITREClassifier directly so joblib can deserialise the .pkl
on Render without needing soc_analyst.py present.

Endpoints:
  GET  /             — service info
  GET  /api/health   — liveness + model status
  POST /api/triage   — full triage
  GET  /api/stats    — aggregate stats
  GET  /api/recent   — last N predictions
"""

import os, re, csv, time
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify
from flask_cors import CORS

# ── Core ML / numeric imports ─────────────────────────────────────────────────
import numpy as np
import joblib
import requests as _requests
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import TruncatedSVD
from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.multiclass import OneVsRestClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV

# ─────────────────────────────────────────────────────────────────────────────
# CUSTOM CLASSES — must be defined here so joblib.load() can unpickle the .pkl
# These are copied verbatim from soc_analyst.py
# ─────────────────────────────────────────────────────────────────────────────

class StackedTfidfEncoder:
    def __init__(self, n_lsa=120):
        self.word_vec = TfidfVectorizer(
            ngram_range=(1, 2), max_features=6000,
            sublinear_tf=True, min_df=2, analyzer="word")
        self.char_vec = TfidfVectorizer(
            ngram_range=(3, 6), max_features=4000,
            sublinear_tf=True, min_df=3, analyzer="char_wb")
        self.lsa = TruncatedSVD(n_components=n_lsa, random_state=42)

    def fit_transform(self, texts):
        W = self.word_vec.fit_transform(texts)
        C = self.char_vec.fit_transform(texts)
        return self.lsa.fit_transform(hstack([W, C]))

    def transform(self, texts):
        W = self.word_vec.transform(texts)
        C = self.char_vec.transform(texts)
        return self.lsa.transform(hstack([W, C]))


class TwoStagePriorityClassifier:
    def __init__(self):
        self.stage1 = CalibratedClassifierCV(
            LinearSVC(class_weight="balanced", max_iter=3000, C=0.8),
            cv=3, method="sigmoid")
        self.stage2 = CalibratedClassifierCV(
            RandomForestClassifier(
                n_estimators=300, class_weight="balanced",
                max_depth=15, random_state=42, n_jobs=1),
            cv=3, method="sigmoid")

    def fit(self, X, y):
        self.stage1.fit(X, (y == 2).astype(int))
        mask = y != 2
        if mask.sum() > 0:
            self.stage2.fit(X[mask], y[mask])
        return self

    def predict(self, X):
        s1  = self.stage1.predict(X)
        out = np.where(s1 == 1, 2, -1)
        nh  = out == -1
        if nh.sum() > 0:
            out[nh] = self.stage2.predict(X[nh])
        return out

    def predict_proba_max(self, X):
        s1_p = self.stage1.predict_proba(X)[:, 1]
        s2_p = self.stage2.predict_proba(X).max(axis=1)
        return np.where(self.stage1.predict(X) == 1, s1_p, s2_p)


class MultiLabelMITREClassifier:
    def __init__(self):
        self.mlb = MultiLabelBinarizer()
        self.clf = None

    def fit(self, X, y_lists):
        Y = self.mlb.fit_transform(y_lists)
        self.clf = OneVsRestClassifier(
            LinearSVC(class_weight="balanced", max_iter=3000, C=1.0),
            n_jobs=1)
        self.clf.fit(X, Y)
        return self

    def predict(self, X, threshold=0.0):
        scores = self.clf.decision_function(X)
        if scores.ndim == 1:
            scores = scores.reshape(-1, 1)
        Y_pred = (scores >= threshold).astype(int)
        no_pred = Y_pred.sum(axis=1) == 0
        if no_pred.any():
            for i, idx in zip(np.where(no_pred)[0], scores[no_pred].argmax(axis=1)):
                Y_pred[i, idx] = 1
        return self.mlb.inverse_transform(Y_pred)

    def predict_proba_max(self, X):
        scores = self.clf.decision_function(X)
        if scores.ndim == 1:
            scores = scores.reshape(-1, 1)
        return (1 / (1 + np.exp(-scores))).max(axis=1)


# ─────────────────────────────────────────────────────────────────────────────
# FLASK APP
# ─────────────────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, origins=[
    "http://localhost:3000",
    "http://localhost:3001",
    r"https://.*\.vercel\.app",
    os.environ.get("FRONTEND_URL", ""),
], supports_credentials=False)

# ── Model path — searches api/ folder first, then repo root ──────────────────
def _find_model() -> Path:
    candidates = [
        Path(__file__).parent / "soc_models_v4.pkl",
        Path(__file__).parent.parent / "soc_models_v4.pkl",
        Path(os.environ.get("MODEL_PATH", "soc_models_v4.pkl")),
    ]
    for c in candidates:
        if c.exists():
            return c
    return candidates[0]

MODEL_PKL  = _find_model()
LOG_CSV    = MODEL_PKL.parent / "prediction_log_v4.csv"
VT_API_KEY = os.environ.get("VT_API_KEY", "")

_bundle   = None
_load_err = ""

# ─────────────────────────────────────────────────────────────────────────────
# DOMAIN CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
PRIORITY_INV = {0: "Low", 1: "Medium", 2: "High"}

HEURISTICS_KEYWORDS = [
    "ransomware", "encrypted files", "shadow copy", "vssadmin", "wbadmin delete",
    "encoded powershell", "base64", "invoke-expression", "iex(", "bypass executionpolicy",
    "mimikatz", "lsass", "pass-the-hash", "pass the hash", "credential dump",
    "seimpersonateprivilege", "reg save sam",
    "exfiltration", "data loss", "user downloading huge data",
    "vm shutdown", "firewall disconnect", "server down", "device disconnect",
    "unexpected power off", "system halt", "arcsight dropping events",
    "arcsight connector shutdown",
    "lateral movement", "domain controller",
    "admin group modification", "admin role removed", "net localgroup administrators",
    "certutil -decode", "bitsadmin /transfer", "whoami /priv",
    "malware beaconing", "malware outbreak", "network sniffing",
    "sap application server stopped", "sap audit configuration",
    "critical asset down", "impossible travel", "two different geograph",
    "authentication failure followed by successful",
    "account created or deleted using critical service account",
]
_HIGH_PAT = re.compile(
    "|".join(re.escape(k) for k in sorted(HEURISTICS_KEYWORDS, key=len, reverse=True)),
    re.IGNORECASE,
)

PRIVATE_IP_RE      = re.compile(r"^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.|0\.0\.0\.0)")
INTERNAL_DOMAIN_RE = re.compile(r"bharatpetroleum\.(?:com|in)|corp\.|localhost|\.local$|internal\.", re.IGNORECASE)
_IP_RE  = re.compile(r'\b((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
_URL_RE = re.compile(
    r'(?:https?://)?(?:www\.)?([a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,}){1,3})(?:/[^\s\]\)\'"<>]*)?',
    re.IGNORECASE,
)
_SKIP_TOKENS = re.compile(
    r'(?:virustotal|microsoft|google|office365?|corp|internal|localhost|bharatpetroleum|windows|linux|ubuntu)',
    re.IGNORECASE,
)

PLAYBOOKS = {
    "Impact": [
        "Query hypervisor / vSphere audit logs for initiating entity immediately.",
        "Trigger HA network routing failovers; verify connector uptime telemetry.",
        "Escalate to OT/ICS security team if industrial assets are affected.",
        "Declare P1 bridge — engage Incident Commander.",
        "Document blast radius and initiate DR runbook.",
    ],
    "Defense Evasion": [
        "Issue automated device isolation command via EDR console.",
        "Terminate active parent process tree; extract volatile memory.",
        "Submit artefacts to sandboxed detonation chamber.",
        "Patch/re-image host post forensic collection.",
        "Update EDR detection rules with new IOC hashes.",
    ],
    "Privilege Escalation": [
        "Immediate account-state audit in Active Directory / Azure AD.",
        "Force credential rotation; invalidate all session tokens.",
        "Enable conditional-access MFA on affected identity tier.",
        "Review PAM logs for lateral movement traces.",
        "Notify CISO and document privilege escalation chain.",
    ],
    "Credential Access": [
        "Lock and reset credentials for all involved accounts.",
        "Pull authentication logs from SIEM for timeline reconstruction.",
        "Invalidate session tokens and OAuth grants; reset MFA seeds.",
        "Scan for password spray / brute-force patterns across the subnet.",
        "Monitor for follow-on lateral movement or exfiltration activity.",
    ],
    "Reconnaissance": [
        "Block source IPs at perimeter firewall and WAF.",
        "Enrich indicators via TI platforms (VirusTotal, MISP).",
        "Flag source entity in UEBA for elevated monitoring.",
        "Review proxy/DNS logs for associated scanning patterns.",
        "Correlate with known threat-actor profiles.",
    ],
    "Initial Access": [
        "Isolate ingress endpoint; revoke abused access token.",
        "Capture network flow telemetry for C2 beaconing.",
        "Block associated domains and IPs at DNS and firewall.",
        "Initiate full AV + EDR scan on compromised host.",
        "Preserve forensic evidence before any remediation.",
    ],
    "Execution": [
        "Terminate suspicious process tree; collect memory + CLI args.",
        "Quarantine the binary or script involved.",
        "Cross-reference file hash against threat intelligence.",
        "Re-image endpoint if persistence artefacts found.",
        "Update application allowlist to block re-execution.",
    ],
    "Persistence": [
        "Identify and remove artefact (registry key, task, service).",
        "Audit all admin and service accounts on the affected host.",
        "Scan adjacent hosts for lateral spread.",
        "Restore from verified clean baseline.",
        "Update SIEM rules to flag similar persistence TTPs.",
    ],
    "Lateral Movement": [
        "Segment the affected VLAN immediately.",
        "Identify all systems the threat actor pivoted through.",
        "Revoke shared credentials and service account tokens.",
        "Audit SMB/RDP/WMI activity logs across the subnet.",
        "Deploy honeypots on adjacent segments.",
    ],
    "Exfiltration": [
        "Block egress channels (DNS tunnelling, FTP, cloud uploads).",
        "Identify and classify data accessed using DLP logs.",
        "Notify DPO; assess breach notification obligations.",
        "Preserve network captures for legal proceedings.",
        "Initiate data owner notification and impact assessment.",
    ],
}
DEFAULT_PLAYBOOK = [
    "Escalate to L2/L3 SOC analyst for manual review.",
    "Capture and preserve all relevant log artefacts.",
    "Apply network micro-segmentation around the affected asset.",
    "Notify asset owner and conduct impact assessment.",
    "Document findings in the incident management platform.",
]

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _get_playbook(tags):
    for t in tags:
        if t in PLAYBOOKS:
            return PLAYBOOKS[t]
    return DEFAULT_PLAYBOOK


def _heuristic_priority(ticket_name, description, threat_desc=""):
    combined = f"{ticket_name} {description} {threat_desc}"
    return 2 if _HIGH_PAT.search(combined) else None


def _extract_iocs(text):
    all_ips     = list(dict.fromkeys(_IP_RE.findall(text)))
    public_ips  = [ip for ip in all_ips if not PRIVATE_IP_RE.match(ip)]
    private_ips = [ip for ip in all_ips if PRIVATE_IP_RE.match(ip)]
    raw_domains = [
        m.group(1).lower() for m in _URL_RE.finditer(text)
        if m.group(1) and len(m.group(1)) > 4 and not _SKIP_TOKENS.search(m.group(1))
    ]
    domains = list(dict.fromkeys(d for d in raw_domains if not INTERNAL_DOMAIN_RE.search(d)))
    return {"public_ips": public_ips, "private_ips": private_ips, "domains_urls": domains}


def _vt_lookup_ip(ip, api_key):
    try:
        r = _requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": api_key}, timeout=12,
        )
        if r.status_code != 200:
            return {"ioc": ip, "type": "ip", "error": f"HTTP {r.status_code}"}
        a = r.json()["data"]["attributes"]
        s = a.get("last_analysis_stats", {})
        return {
            "ioc": ip, "type": "ip", "error": None,
            "status":     "malicious" if s.get("malicious", 0) > 0 else (
                          "suspicious" if s.get("suspicious", 0) > 0 else "clean"),
            "malicious":  s.get("malicious", 0),
            "suspicious": s.get("suspicious", 0),
            "harmless":   s.get("harmless", 0),
            "country":    a.get("country", "—"),
            "asn":        str(a.get("asn", "—")),
            "owner":      a.get("as_owner", "—"),
            "reputation": a.get("reputation", 0),
            "tags":       a.get("tags", []),
            "last_analysis": datetime.utcfromtimestamp(a["last_analysis_date"]).strftime("%Y-%m-%d")
                             if "last_analysis_date" in a else "—",
        }
    except Exception as e:
        return {"ioc": ip, "type": "ip", "error": str(e)}


def _vt_lookup_domain(domain, api_key):
    try:
        r = _requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain.rstrip('/').lower()}",
            headers={"x-apikey": api_key}, timeout=12,
        )
        if r.status_code != 200:
            return {"ioc": domain, "type": "domain", "error": f"HTTP {r.status_code}"}
        a = r.json()["data"]["attributes"]
        s = a.get("last_analysis_stats", {})
        return {
            "ioc": domain, "type": "domain", "error": None,
            "status":    "malicious" if s.get("malicious", 0) > 0 else (
                         "suspicious" if s.get("suspicious", 0) > 0 else "clean"),
            "malicious":  s.get("malicious", 0),
            "suspicious": s.get("suspicious", 0),
            "harmless":   s.get("harmless", 0),
            "categories": list(set(a.get("categories", {}).values()))[:4],
            "reputation": a.get("reputation", 0),
            "registrar":  a.get("registrar", "—"),
            "last_analysis": datetime.utcfromtimestamp(a["last_analysis_date"]).strftime("%Y-%m-%d")
                             if "last_analysis_date" in a else "—",
        }
    except Exception as e:
        return {"ioc": domain, "type": "domain", "error": str(e)}


def _load_models():
    global _bundle, _load_err
    if _bundle:
        return True
    if not MODEL_PKL.exists():
        _load_err = (
            f"Model file not found: {MODEL_PKL}. "
            "Run soc_analyst.py to train, then copy soc_models_v4.pkl into the api/ folder."
        )
        return False
    try:
        _bundle = joblib.load(str(MODEL_PKL))
        return True
    except Exception as e:
        _load_err = str(e)
        return False


def _explain(text, enc, model_a, top_n=5):
    tokens = text.lower().split()
    if not tokens:
        return []
    try:
        base_conf = float(model_a.predict_proba_max(enc.transform([text]))[0])
        imps = []
        for i, tok in enumerate(tokens):
            ablated  = " ".join(t for j, t in enumerate(tokens) if j != i)
            conf     = float(model_a.predict_proba_max(enc.transform([ablated]))[0])
            imps.append({"token": tok, "delta": round(base_conf - conf, 4)})
        imps.sort(key=lambda x: -abs(x["delta"]))
        return imps[:top_n]
    except Exception:
        return []


def _log_prediction(data):
    exists = LOG_CSV.exists()
    try:
        with open(LOG_CSV, "a", newline="") as f:
            w = csv.DictWriter(f, fieldnames=[
                "timestamp", "ticket_name", "description_snippet",
                "predicted_priority", "predicted_mitre", "confidence",
                "vt_verdict", "analyst_override",
            ])
            if not exists:
                w.writeheader()
            w.writerow(data)
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return jsonify({
        "service":   "Synapse SOC API",
        "version":   "2.0",
        "endpoints": ["/api/health", "/api/triage", "/api/stats", "/api/recent"],
    })


@app.route("/api/health")
def health():
    ok = _load_models()
    return jsonify({
        "status":     "ok" if ok else "degraded",
        "model_ok":   ok,
        "model_path": str(MODEL_PKL),
        "error":      _load_err if not ok else None,
        "timestamp":  datetime.utcnow().isoformat(),
    }), 200 if ok else 503


@app.route("/api/triage", methods=["POST"])
def triage():
    body = request.get_json(force=True, silent=True) or {}

    ticket_name       = body.get("ticket_name", "").strip()
    description       = body.get("description", "").strip()
    threat_desc       = body.get("threat_desc", "").strip()
    source_ip         = body.get("source_ip", "").strip()
    dest_ip           = body.get("dest_ip", "").strip()
    affected_hostname = body.get("affected_hostname", "").strip()
    run_vt            = body.get("run_vt", False)
    vt_key            = body.get("vt_api_key", VT_API_KEY).strip()

    if not ticket_name:
        return jsonify({"error": "ticket_name is required"}), 400

    if not _load_models():
        return jsonify({"error": _load_err}), 503

    enc = _bundle["encoder"]
    m_a = _bundle["model_a"]
    m_b = _bundle["model_b"]

    # Priority
    heuristic  = _heuristic_priority(ticket_name, description, threat_desc)
    combined   = f"{ticket_name} {description} {threat_desc}".lower().strip()
    feat       = enc.transform([combined])
    ml_pri     = int(m_a.predict(feat)[0])
    final_pri  = max(heuristic if heuristic is not None else ml_pri, ml_pri)
    confidence = float(m_a.predict_proba_max(feat)[0])
    if heuristic == 2:
        confidence = max(confidence, 0.90)
    auto_dispatch = confidence >= 0.60

    # MITRE
    mitre_raw  = m_b.predict(feat)[0]
    mitre_tags = list(mitre_raw) if mitre_raw else ["Unknown"]
    playbook   = _get_playbook(mitre_tags)

    # Explainability
    top_tokens = _explain(combined, enc, m_a)

    # IOC extraction
    all_text = " ".join(filter(None, [
        ticket_name, description, threat_desc,
        source_ip, dest_ip, affected_hostname,
    ]))
    iocs = _extract_iocs(all_text)
    if dest_ip and not PRIVATE_IP_RE.match(dest_ip) and dest_ip not in iocs["public_ips"]:
        iocs["public_ips"].insert(0, dest_ip)
    if source_ip and PRIVATE_IP_RE.match(source_ip) and source_ip not in iocs["private_ips"]:
        iocs["private_ips"].insert(0, source_ip)
    if affected_hostname:
        h = affected_hostname.lstrip("https://").lstrip("http://").lstrip("www.").rstrip("/")
        if h and not INTERNAL_DOMAIN_RE.search(h) and h not in iocs["domains_urls"]:
            iocs["domains_urls"].insert(0, h)

    # VT enrichment
    enrichment = {
        "verdict": "NO_IOCS", "ip_results": [], "domain_results": [],
        "summary": "VirusTotal enrichment not requested.",
    }
    if run_vt and vt_key:
        ip_results, domain_results = [], []
        for ip in iocs["public_ips"][:3]:
            ip_results.append(_vt_lookup_ip(ip, vt_key))
            time.sleep(15.1)
        for dom in iocs["domains_urls"][:2]:
            domain_results.append(_vt_lookup_domain(dom, vt_key))
            time.sleep(15.1)
        all_r = ip_results + domain_results
        if not all_r:
            verdict = "NO_IOCS"
        elif any(r.get("status") == "malicious" for r in all_r):
            verdict = "MALICIOUS"
        elif any(r.get("status") == "suspicious" for r in all_r):
            verdict = "SUSPICIOUS"
        elif any(r.get("error") for r in all_r):
            verdict = "UNKNOWN"
        else:
            verdict = "CLEAN"
        enrichment = {
            "verdict":        verdict,
            "ip_results":     ip_results,
            "domain_results": domain_results,
            "summary":        f"{len(ip_results)} IP(s) + {len(domain_results)} domain(s) analysed",
        }
    elif run_vt and not vt_key:
        enrichment["summary"] = "VT API key not configured. Set VT_API_KEY env variable."
        enrichment["verdict"] = "UNKNOWN"

    # Log
    _log_prediction({
        "timestamp":           datetime.utcnow().isoformat(),
        "ticket_name":         ticket_name,
        "description_snippet": description[:120],
        "predicted_priority":  PRIORITY_INV[final_pri],
        "predicted_mitre":     "|".join(mitre_tags),
        "confidence":          round(confidence, 3),
        "vt_verdict":          enrichment["verdict"],
        "analyst_override":    "",
    })

    return jsonify({
        "priority":        final_pri,
        "priority_label":  PRIORITY_INV[final_pri],
        "confidence":      round(confidence, 3),
        "auto_dispatch":   auto_dispatch,
        "heuristic_fired": heuristic == 2,
        "mitre_tactics":   mitre_tags,
        "playbook":        playbook,
        "top_tokens":      top_tokens,
        "iocs":            iocs,
        "enrichment":      enrichment,
    })


@app.route("/api/stats")
def stats():
    if not LOG_CSV.exists():
        return jsonify({"total": 0, "by_priority": {}, "by_verdict": {}, "auto_rate": 0})
    with open(LOG_CSV) as f:
        rows = list(csv.DictReader(f))
    if not rows:
        return jsonify({"total": 0, "by_priority": {}, "by_verdict": {}, "auto_rate": 0})
    by_pri, by_verd = {}, {}
    for r in rows:
        p = r.get("predicted_priority", "Unknown")
        v = r.get("vt_verdict", "UNKNOWN")
        by_pri[p]  = by_pri.get(p, 0)  + 1
        by_verd[v] = by_verd.get(v, 0) + 1
    high_conf = sum(1 for r in rows if float(r.get("confidence", 0)) >= 0.6)
    return jsonify({
        "total":        len(rows),
        "by_priority":  by_pri,
        "by_verdict":   by_verd,
        "auto_rate":    round(high_conf / len(rows), 3) if rows else 0,
        "last_updated": rows[-1]["timestamp"] if rows else None,
    })


@app.route("/api/recent")
def recent():
    n = int(request.args.get("n", 10))
    if not LOG_CSV.exists():
        return jsonify([])
    with open(LOG_CSV) as f:
        rows = list(csv.DictReader(f))
    return jsonify(rows[-n:][::-1])


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    print(f"Synapse API v2 starting on http://0.0.0.0:{port}")
    print(f"Model path : {MODEL_PKL}")
    print(f"Model found: {MODEL_PKL.exists()}")
    _load_models()
    app.run(host="0.0.0.0", port=port, debug=False)
