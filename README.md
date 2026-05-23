# Synapse — AI-Driven SOC Analyst

Full-stack web application wrapping the BPCL SOC ML pipeline (soc_analyst.py v4.1).

## Stack
- **Frontend**: Next.js 14 + TypeScript + Tailwind CSS
- **Backend**: Flask API (Python)
- **ML**: Two-stage priority classifier + multi-label MITRE classifier + VirusTotal v3

## Project Layout

```
synapse/
├── api/
│   ├── app.py              ← Flask API (exposes /api/triage, /api/stats, /api/recent)
│   └── requirements.txt
├── frontend/               ← Next.js app
│   ├── app/
│   │   ├── page.tsx        ← Landing page
│   │   ├── triage/page.tsx ← Triage console
│   │   └── dashboard/      ← Analytics dashboard
│   ├── components/
│   │   └── Nav.tsx
│   └── lib/api.ts          ← Typed API client
├── start_api.sh
├── start_frontend.sh
└── README.md

# Files expected alongside synapse/ (from soc_analyst.py):
soc_analyst.py
soc_models_v4.pkl           ← created when you run soc_analyst.py
prediction_log_v4.csv       ← created automatically on first triage
Tickets_Details.xlsx
AISAAC_Tickets.xlsx
List_Of_Tickets_Jan-Feb.xlsx
```

## Quick Start

### Step 1 — Train the ML models (one-time)
```bash
# Make sure all 3 Excel files are in the same folder as soc_analyst.py
pip install pandas scikit-learn scipy joblib imbalanced-learn openpyxl requests
python soc_analyst.py
# This creates soc_models_v4.pkl and prediction_log_v4.csv
```

### Step 2 — Start the Flask API
```bash
pip install flask flask-cors
# Optional: export VT_API_KEY='your_virustotal_key'
bash synapse/start_api.sh
# API running at http://localhost:5050
```

### Step 3 — Start the frontend
```bash
cd synapse/frontend
npm install
npm run dev
# App running at http://localhost:3000
```

### Step 4 — Open the app
Visit **http://localhost:3000** in your browser.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/triage` | Full ticket triage |
| `GET`  | `/api/health` | Model status |
| `GET`  | `/api/stats`  | Aggregate stats from log |
| `GET`  | `/api/recent?n=10` | Last N predictions |

### POST /api/triage — Request body
```json
{
  "ticket_name":       "string (required)",
  "description":       "string (required)",
  "threat_desc":       "string (optional)",
  "source_ip":         "string (optional)",
  "dest_ip":           "string (optional)",
  "affected_hostname": "string (optional)",
  "run_vt":            false,
  "vt_api_key":        "string (optional — overrides env var)"
}
```

### POST /api/triage — Response
```json
{
  "priority":        0,
  "priority_label":  "Low",
  "confidence":      0.873,
  "auto_dispatch":   true,
  "heuristic_fired": false,
  "mitre_tactics":   ["Reconnaissance", "Initial Access"],
  "playbook":        ["Step 1...", "Step 2..."],
  "top_tokens":      [{"token": "powershell", "delta": 0.042}],
  "iocs": {
    "public_ips":   ["198.38.85.149"],
    "domains_urls": ["www.examsegg.com"],
    "private_ips":  ["10.81.2.75"]
  },
  "enrichment": {
    "verdict":        "CLEAN",
    "ip_results":     [...],
    "domain_results": [...]
  }
}
```

## VirusTotal Setup (Optional)
```bash
# Get a free API key at https://www.virustotal.com/gui/join-us
# Free tier: 4 requests/min, 500/day
export VT_API_KEY='your_key_here'
```
Or paste it directly in the Triage Console's VT key field.

## Pages

| Page | Route | Description |
|------|-------|-------------|
| Home | `/` | Feature overview and quick-start |
| Triage | `/triage` | Main triage console — paste a ticket, get full analysis |
| Dashboard | `/dashboard` | Live charts from prediction log |

## Customisation

### Add heuristic keywords (no retraining needed)
Edit `HEURISTICS_KEYWORDS` in `synapse/api/app.py`:
```python
HEURISTICS_KEYWORDS = [
    ...
    "your new keyword here",
]
```

### Change confidence gate
```python
# In app.py triage() function
auto_dispatch = confidence >= 0.60   # lower = more auto-dispatches
```

### Point to different Excel files
Edit `ALL_FILES` in `soc_analyst.py` before training.
