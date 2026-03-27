# 🛡️ ACIRA — Autonomous Cyber Incident Response Agent

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.x-005571?style=for-the-badge&logo=elasticsearch&logoColor=white)
![Ollama](https://img.shields.io/badge/Ollama-Mistral-black?style=for-the-badge&logo=ollama&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-IForest-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**A production-grade, end-to-end AI-powered cybersecurity pipeline that autonomously ingests, analyzes, correlates, scores, and responds to security incidents — no human in the loop required.**

[Pipeline Overview](#-pipeline-overview) · [ML Details](#-machine-learning-anomaly-detection) · [Correlation Engine](#-correlation-engine) · [Fidelity Scoring](#-fidelity-scoring-system) · [LLM Playbooks](#-llm-powered-playbook-generation) · [Setup](#-installation--setup)

</div>

---

## 📌 What is ACIRA?

Modern Security Operations Centers (SOCs) are overwhelmed. Analysts manually sift through millions of security events daily, with average threat detection times measured in hours or days. **ACIRA closes this gap.**

ACIRA is a fully autonomous, modular cybersecurity pipeline built for banking and financial institutions. It:

1. **Ingests** structured security logs from JSON files or live Elasticsearch indices
2. **Engineers** behavioral features from raw log events per user
3. **Detects** anomalous behavior using **Isolation Forest** ML with normalized scoring
4. **Correlates** individual anomalies into coherent multi-step **incidents** using sequence pattern rules
5. **Scores** each incident with a composite **fidelity score** combining ML + rules + correlation
6. **Classifies** incidents as Low / Medium / High severity
7. **Generates** structured SOC response **playbooks** using Mistral LLM via Ollama
8. **Presents** all results on a real-time **web dashboard**

> ACIRA replaces hours of manual analyst work with a deterministic, explainable, auditable pipeline that runs end-to-end in seconds.

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          ACIRA PIPELINE                             │
│                                                                     │
│  ┌──────────┐    ┌────────────┐    ┌──────────┐    ┌────────────┐  │
│  │  JSON /  │    │  Feature   │    │  Isolation│    │Correlation │  │
│  │   ES     │───▶│Engineering │───▶│  Forest  │───▶│  Engine   │  │
│  │  Logs    │    │(ingestion) │    │ (anomaly)│    │(incidents) │  │
│  └──────────┘    └────────────┘    └──────────┘    └────────────┘  │
│                                                           │         │
│  ┌───────────┐    ┌──────────┐    ┌──────────────────────▼──────┐  │
│  │ Dashboard │◀───│ FastAPI  │◀───│   Fidelity Scoring &        │  │
│  │   (HTML)  │    │  /analyze│    │   LLM Playbook Generation   │  │
│  └───────────┘    └──────────┘    └─────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 📂 Project Structure

```
acira/
├── main.py                        # FastAPI app — orchestrates entire pipeline
├── dashboard.html                 # Frontend dashboard (vanilla JS + Chart.js)
├── requirements.txt               # Python dependencies
│
├── core/
│   ├── ingestion.py               # Log parsing, Elasticsearch I/O, data masking
│   ├── feature_engineering.py     # Behavioral feature extraction
│   ├── anomaly.py                 # Isolation Forest anomaly detection
│   ├── correlation.py             # Incident detection via sequence analysis
│   ├── scoring.py                 # Fidelity scoring + severity classification
│   ├── playbook.py                # LLM-based SOC playbook generation
│   ├── vector_loader.py           # PCA vector retrieval from Elasticsearch
│   ├── vector_upload.py           # Uploads pre-computed feature vectors to ES
│   ├── vector_store.py            # ES index setup for vectors
│   ├── synthetic_log_generator.py # Realistic log generation for testing
│   ├── es_setup.py                # Elasticsearch index creation + mappings
│   └── es_reset.py                # Index reset/cleanup utility
│
└── data/
    └── sample_logs_100.json       # Sample synthetic logs for offline testing
```

### Module Breakdown

| Module | Responsibility |
|--------|---------------|
| `ingestion.py` | Parses raw JSON logs into typed `LogEvent` objects. Handles ES ingestion and retrieval. Masks PII (file paths, usernames, hashes) before any external processing. |
| `feature_engineering.py` | Extracts 10 behavioral features per event: login hour, odd-hour flags, failed login counts, resource sensitivity, IP origin risk, geo anomaly, threat intel scores. |
| `anomaly.py` | Trains Isolation Forest on the feature matrix and assigns normalized anomaly scores `[0.0, 1.0]` to every event. Higher score = more anomalous. |
| `correlation.py` | Groups events by `user_id`, sorts by timestamp, and scans each user's sequence for known attack patterns. Forms `Incident` objects with full metrics. |
| `scoring.py` | Computes a composite fidelity score from three signals: anomaly score, correlation strength, and rule-based severity. Maps final score to a severity label. |
| `playbook.py` | Constructs a structured JSON incident summary and sends it as a SOC-analyst prompt to Mistral via Ollama subprocess. Returns a formatted incident response plan. |
| `vector_loader.py` | Fetches pre-computed PCA feature vectors from the `acira_vectors` Elasticsearch index for fast anomaly detection without re-engineering features at runtime. |
| `vector_upload.py` | Pre-processes logs into feature vectors and bulk-uploads them to Elasticsearch for vector-backed anomaly scoring. |
| `synthetic_log_generator.py` | Generates realistic synthetic banking logs (100K events) with injected fraud sequences (brute-force → escalation, password change → transaction) for testing. |
| `es_setup.py` / `es_reset.py` | Manage Elasticsearch index lifecycle: creation with proper mappings, and clean resets between test runs. |

---

## 🔄 Pipeline Overview

### Stage 1 — Log Ingestion (`ingestion.py`)

**Problem:** Raw security logs arrive as unstructured JSON with no typing, inconsistent fields, and sensitive PII scattered throughout.

**Solution:** `LogEvent` is a typed Python dataclass that enforces structure. The ingestion layer:
- Parses ISO 8601 timestamps into `datetime` objects for time-series operations
- Fills optional fields (`dns_query`, `file_path`, `hostname`, `geo`) safely with `None` defaults
- Applies field-level **data masking** (replacing sensitive values with `*` strings) before packaging events for LLM consumption
- Supports both JSON file loading (`load_logs()`) and live Elasticsearch retrieval (`load_logs_from_es()`) behind consistent interfaces

```python
# Example LogEvent fields
user_id:               "user_042"
source_ip_address:     "45.129.33.187"
event_type:            "privilege_escalation"
timestamp:             datetime(2026, 2, 17, 3, 14, 59)
resource_accessed:     "core_banking_admin_panel"
threat_intel_score:    94
anomaly_score:         None   ← assigned later in pipeline
```

---

### Stage 2 — Feature Engineering (`feature_engineering.py`)

**Problem:** ML models need numerical vectors, not raw event strings. Behavioral patterns must be quantified per-user, per-event.

**Solution:** For each event, 10 features are extracted from behavioral signals:

| Feature | Description | Why It Matters |
|---------|-------------|----------------|
| `login_hour` | Hour of the event (0–23) | Identifies off-hours access |
| `odd_hour_flag` | 1 if hour < 6 or > 22 | Direct night-time activity signal |
| `failed_login_count` | Total failed logins for this user across all events | Quantifies brute-force pressure |
| `sensitive_access_flag` | 1 if resource contains "customer" | Flags high-value target access |
| `privilege_escalation_flag` | 1 if event_type is privilege_escalation | Direct attack indicator |
| `suspicious_ip_flag` | 1 if source IP is not in 192.x.x.x range | External IP access |
| `high_threat_intel_flag` | 1 if threat_intel_score > 70 | Integrates external threat feeds |
| `foreign_geo_flag` | 1 if geo != "India" | Geographic anomaly detection |
| `password_change_flag` | 1 if event_type is password_change | Pre-fraud signal |
| `transaction_flag` | 1 if event_type is transaction_initiated | Financial action indicator |

The result is a `pandas.DataFrame` of shape `(n_events, 10)` — a dense numerical matrix aligned 1:1 with `events`.

---

### Stage 3 — Anomaly Detection (`anomaly.py`)

**Problem:** Which individual events are statistically abnormal compared to baseline behavior?

**Solution:** Isolation Forest is trained on the full feature matrix and produces an anomaly score per event.

*See the [ML section below](#-machine-learning-anomaly-detection) for full technical details.*

---

### Stage 4 — Incident Correlation (`correlation.py`)

**Problem:** A single anomalous event is noise. A sequence of anomalous events with a recognizable attack pattern is an **incident**.

**Solution:** Events are grouped by `user_id`, sorted chronologically, and scanned for known attack sequences.

*See the [Correlation Engine section below](#-correlation-engine) for full technical details.*

---

### Stage 5 — Fidelity Scoring + Severity (`scoring.py`)

**Problem:** Not all incidents are equally serious. A scoring system must aggregate ML confidence, correlation quality, and rule-based risk into a single actionable signal.

**Solution:** A weighted composite fidelity score is computed per incident.

*See the [Fidelity Scoring section below](#-fidelity-scoring-system) for the formula.*

---

### Stage 6 — LLM Playbook Generation (`playbook.py`)

**Problem:** Even after an incident is detected and scored, a human analyst still needs to know exactly what to do — containment steps, eradication procedures, reporting obligations.

**Solution:** A structured SOC-analyst prompt is constructed from the incident data and sent to **Mistral** running locally via Ollama. The model returns a formatted 4-section incident response plan.

*See the [LLM Playbook section below](#-llm-powered-playbook-generation) for full details.*

---

### Stage 7 — Dashboard (`dashboard.html`)

The frontend provides a single-page interface with:
- **Log Ingestion Panel** — file picker to upload a JSON log file
- **Severity Distribution Chart** — real-time doughnut chart via Chart.js
- **Incidents Table** — sortable table with correlation strength, fidelity score, anomaly score, and severity badge per incident
- **Playbook Panel** — renders the LLM-generated response plan per incident with fullscreen modal support
- **Stats Cards** — live counts of total incidents, average fidelity, average correlation, critical threat count

All dashboard data is fetched from the FastAPI backend (`/analyze`, `/incidents`, `/stats`, `/playbook/{id}`).

---

## 🤖 Machine Learning: Anomaly Detection

### Why Isolation Forest?

Isolation Forest is a **tree-based unsupervised anomaly detection** algorithm that works by randomly partitioning the feature space. Anomalous observations are isolated in fewer splits than normal ones, because they are sparse and different.

**Why it is the right choice for ACIRA:**

| Criterion | Isolation Forest | Alternatives |
|-----------|-----------------|--------------|
| Works without labels | ✅ Yes (unsupervised) | LSTM needs labels; SVM needs tuning |
| Handles high-dimensional behavioral data | ✅ Yes | KNN degrades in high dims |
| Fast inference on 100K+ events | ✅ O(n log n) | Deep models are too slow |
| Interpretable contamination parameter | ✅ Yes | Neural nets are black boxes |
| No assumptions about data distribution | ✅ Yes | Gaussian models assume normality |

### Contamination Parameter

```python
model = IForest(contamination=0.2, random_state=42)
```

`contamination=0.2` tells the model that approximately **20% of the dataset is expected to be anomalous**. This is calibrated for the synthetic dataset where ~2% of logs are injected attack events, but surrounding behavioral drift raises the realistic anomaly rate. Adjust this based on your environment's baseline false-positive rate.

### Score Normalization

Raw Isolation Forest scores can be negative (more anomalous = more negative). ACIRA normalizes them to `[0.0, 1.0]` using min-max scaling:

```python
normalized_scores = (scores - min_score) / (max_score - min_score + 1e-8)
```

The `1e-8` term prevents division-by-zero when all scores are identical. After normalization:
- `0.0` → most normal event in the dataset
- `1.0` → most anomalous event in the dataset

This normalized score is stored on each `LogEvent.anomaly_score` and flows into the fidelity calculation.

### Why Anomaly Detection Alone Is Not Enough

Isolation Forest scores **individual events in isolation**. A single `privilege_escalation` from a trusted IP might score low. But the same event preceded by 3 `login_failed` events from an external IP, all within 5 minutes, is a confirmed brute-force attack.

Anomaly detection provides the **signal**. Correlation provides the **narrative**.

---

## 🔗 Correlation Engine

### Core Concept

The correlation engine operates on a fundamental SIEM principle: **threat actors do not act in a single event**. Real attacks are multi-step sequences that unfold over time, often across multiple systems. Detecting these sequences is what separates an **alert** from an **incident**.

### Grouping Logic

```
events → group by user_id → sort by timestamp → scan sequence → match patterns
```

For each user:
1. All events are sorted chronologically
2. Events are accumulated into a growing `sequence` list
3. At each step, the sequence is checked against known attack pattern conditions
4. On the first pattern match, an `Incident` object is created and the user's scan stops

### Detected Attack Patterns

#### Pattern 1 — Brute Force → Privilege Escalation

```
login_failed  →  login_failed  →  login_failed  →  privilege_escalation
   (T+0)            (T+1min)          (T+2min)           (T+5min)
```

This is the classic **credential stuffing / brute force** attack chain. An adversary hammers the login system, eventually gains access (possibly via a weak credential), and immediately escalates to admin rights.

**Detection condition:**
```python
has_failed = any(e.event_type == "login_failed" for e in sequence)
has_priv   = any(e.event_type == "privilege_escalation" for e in sequence)
if has_failed and has_priv: → INCIDENT
```

#### Pattern 2 — Banking Fraud: Password Change → Transaction

```
password_change  →  transaction_initiated
     (T+0)                (T+3min)
```

This is the **account takeover fraud** chain prevalent in banking systems. An adversary who gains access to an account immediately changes the password (to lock out the real user) and initiates a transaction before the fraud detection window closes.

**Detection condition:**
```python
has_pwd = any(e.event_type == "password_change" for e in sequence)
has_txn = any(e.event_type == "transaction_initiated" for e in sequence)
if has_pwd and has_txn: → INCIDENT
```

### Fallback Detection

For users who do not match strict pattern rules but exhibit statistically anomalous behavior across multiple events, a **fallback** triggers after full sequence scan:

```python
if not incident_created and len(sequence) >= 5:
    avg_anomaly = mean([e.anomaly_score for e in sequence])
    if avg_anomaly > 0.4:
        → FALLBACK INCIDENT
```

This catches zero-day or novel attack patterns that don't match known rules but are statistically significant.

### Correlation Strength Calculation

For each incident, a `correlation_strength` is computed as a weighted combination:

```
correlation_strength = sigmoid(
    0.3 * resource_criticality
  + 0.2 * time_decay_score
  + 0.2 * ip_risk_score
  + 0.2 * threat_intel_boost
  + pattern_bonus (0.2 for brute-force, 0.25 for fraud chain)
)
```

**Resource criticality weights:**

| Resource | Weight |
|----------|--------|
| `core_banking_admin_panel` | 1.0 |
| `swift_gateway` | 1.0 |
| `customer_financial_db` | 0.9 |
| `employee_db` | 0.7 |
| Default | 0.3 |

**Time decay:** Events clustered within a short window score higher — rapid multi-step attacks are more suspicious than events spread over days.

---

## 📈 Fidelity Scoring System

### The Formula

```
fidelity = (0.5 × avg_anomaly_score)
         + (0.3 × correlation_strength)
         + (0.2 × rule_severity)
```

### Why Weighted Averaging?

Each signal has different reliability and specificity:

| Signal | Weight | Rationale |
|--------|--------|-----------|
| `avg_anomaly_score` | **50%** | Strongest signal — ML-derived from full behavioral context |
| `correlation_strength` | **30%** | High confidence when pattern matches — but rules can miss novel attacks |
| `rule_severity` | **20%** | Deterministic, interpretable, but static — doesn't adapt to new patterns |

### Rule Severity Table

| Event Pattern | Rule Severity Score |
|---------------|-------------------|
| `password_change` + `transaction_initiated` | 0.90 — Critical fraud chain |
| `privilege_escalation` present | 0.85 — Admin compromise |
| `login_failed` ≥ 3 times | 0.60 — Brute force |
| `transaction_initiated` only | 0.40 — Suspicious activity |
| None of the above | 0.20 — Minor anomaly |

### Severity Bands

```python
if fidelity > 0.85 → "High"
elif fidelity > 0.50 → "Medium"
else → "Low"
```

> **Note:** The scoring system is intentionally conservative — a `High` severity requires all three signals to be strong simultaneously.

---

## 🧠 LLM-Powered Playbook Generation

### Why Mistral via Ollama?

| Criterion | Choice | Rationale |
|-----------|--------|-----------|
| **Privacy** | Ollama (local) | No incident data leaves the system. Critical for banking compliance (GDPR, PCI-DSS). |
| **Model** | Mistral 7B | Best-in-class instruction following at 7B params. Fast on CPU. Structured output quality is high. |
| **Determinism** | Structured prompt | Forces output into a rigid 4-section format regardless of input variation. |
| **Cost** | $0 | No API costs — fully self-hosted. |

### Prompt Engineering

The LLM is not given free reign. The prompt is tightly engineered with:

1. **Role priming:** "You are a senior banking SOC analyst" — scopes the model's expertise domain
2. **Grounded input:** Full incident JSON (with masked PII) is embedded — the model cannot hallucinate events
3. **Negative constraints:** "Do NOT hallucinate additional events. Do NOT mention malware unless explicitly present." — prevents confabulation
4. **Conditional instructions:** Maps severity level to expected response depth
5. **Strict output schema:** Forces the 4-section (Containment / Eradication / Recovery / Reporting) format used in real SOC runbooks

```python
prompt = f"""
You are a senior banking SOC analyst.
Incident Data: {json.dumps(incident_summary, indent=2)}

Rules:
- Base response ONLY on provided data.
- If privilege_escalation and db_access → treat as confirmed account compromise.
- If password_change followed by transaction_initiated → account takeover fraud.
- Reference the specific user_id and source_ip_address.
- Do NOT hallucinate additional events.

Return response strictly in this format:
=== INCIDENT RESPONSE PLAN ===
Severity: {severity}
1. Containment: ...
2. Eradication: ...
3. Recovery: ...
4. Reporting: ...
"""
```

### Sample Playbook Output

```
=== INCIDENT RESPONSE PLAN ===

Severity: High

1. Containment:
- Immediately suspend user_042's account access across all banking systems
- Block source IP 45.129.33.187 at the perimeter firewall and WAF
- Revoke all active sessions for user_042 in the SSO/IAM system
- Isolate the core_banking_admin_panel from external network access

2. Eradication:
- Audit all actions performed by user_042 after the privilege_escalation event
- Review admin panel access logs for unauthorized configuration changes
- Reset all credentials that may have been exposed during the session
- Force multi-factor re-enrollment for all admin-level accounts

3. Recovery:
- Restore admin account access only after MFA verification with physical security token
- Re-verify integrity of affected banking records against last known-good backup
- Re-enable account after fraud investigation team clearance
- Implement geo-blocking for admin panel for non-Indian IPs

4. Reporting:
- Escalate to CISO within 1 hour per banking cybersecurity incident policy
- File mandatory RBI cyber incident report within 6 hours of detection
- Preserve all forensic logs for minimum 90 days per compliance requirements
- Notify fraud operations team to review associated transactions for reversal
```

---

## 🔐 Security & Privacy Design

### Data Masking

Sensitive fields are masked **before any LLM call** using the `mask_value()` utility in `ingestion.py`:

```python
def mask_value(value):
    if value is None:
        return None
    return "*" * len(str(value))
```

Masked fields in LLM payloads:

| Field | Example Raw | Example Masked |
|-------|-------------|----------------|
| `file_path` | `C:\Windows\System32\cmd.exe` | `****************************` |
| `file_hash` | `a94a8fe5ccb19ba61c4c0873d391e987` | `********************************` |
| `username` | `rahul.sharma` | `*************` |
| `hostname` | `CORP-LAPTOP-01` | `**************` |

Source IPs and destination IPs are **not masked** — they are essential for SOC containment actions (firewall rules, IP blocking) and are already present in network logs.

### Why This Matters

In banking systems operating under **PCI-DSS**, **RBI Cybersecurity Framework**, and **GDPR**, the exposure of employee usernames, file paths, or internal hostnames to any external system — including a cloud LLM API — is a regulatory violation. ACIRA's local Ollama deployment and field masking ensure the system can operate in production-regulated environments.

---

## ⚡ Design Decisions & Trade-offs

### Modular Architecture

Each stage of the pipeline is an independent Python module with a single responsibility. This means:
- **Individual testability** — run `python core/anomaly.py` standalone to test anomaly scoring
- **Swappability** — replace Isolation Forest with AutoEncoder without touching correlation or scoring
- **Failure isolation** — if ES is down, `feature_df` from `extract_features()` serves as a fallback

### Why Elasticsearch?

| Capability | Why It Matters |
|-----------|----------------|
| Full-text + structured search | Query logs by event_type, user_id, timestamp range simultaneously |
| Horizontal scalability | Handles 100M+ documents with sharding |
| Native vector storage | Stores pre-computed feature vectors alongside raw logs |
| Real-time indexing | Supports streaming log ingestion from SIEMs |
| Industry standard | Integrates with Kibana, Logstash (ELK stack) out of the box |

### Hybrid Detection Strategy

ACIRA uses three complementary detection techniques simultaneously:

```
┌─────────────┐   ┌──────────────┐   ┌──────────────┐
│ ML (IForest)│ + │   Rule-Based │ + │  Correlation │ = INCIDENT
│ (novel,     │   │  (known,     │   │  (multi-step │
│  adaptive)  │   │   fast)      │   │   context)   │
└─────────────┘   └──────────────┘   └──────────────┘
```

- **ML alone** misses patterned attacks that happen to look statistically normal individually
- **Rules alone** miss zero-day or variant attacks not in the rule set
- **Correlation alone** requires every step of a sequence to match exactly — too brittle

The weighted fidelity score that combines all three is **more robust than any single technique**.

### Trade-offs

| Decision | Benefit | Trade-off |
|----------|---------|-----------|
| Isolation Forest | Fast, unsupervised, no labels needed | Not adaptive in real-time; requires retraining as baseline shifts |
| Ollama local LLM | Privacy-preserving, zero cost | Higher latency than cloud APIs; no fine-tuning for domain specificity |
| Synchronous pipeline | Simple, debuggable, deterministic | Cannot process streaming events; full batch required before scoring |
| FastAPI + vanilla JS | Zero build complexity, fast iteration | No state management; dashboard reloads are manual |

---

## 🚀 Installation & Setup

### Prerequisites

- Python 3.11+
- Elasticsearch 8.x (running on `localhost:9200`)
- [Ollama](https://ollama.com/) with Mistral model pulled

### 1. Clone the Repository

```bash
git clone https://github.com/ayushgade06/acira.git
cd acira
```

### 2. Create Virtual Environment

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

**Key dependencies:**

| Package | Purpose |
|---------|---------|
| `fastapi` | REST API framework |
| `uvicorn` | ASGI server |
| `elasticsearch` | ES Python client |
| `pyod` | Isolation Forest (IForest) |
| `pandas` | Feature matrix handling |
| `numpy` | Score normalization |
| `pydantic` | Request validation |

### 4. Start Elasticsearch

```bash
# If using Docker
docker run -d --name es8 -p 9200:9200 -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" elasticsearch:8.13.0
```

### 5. Pull Mistral via Ollama

```bash
ollama pull mistral
```

### 6. Setup Elasticsearch Indices

```bash
python -m core.es_setup
```

### 7. Generate Synthetic Test Logs

```bash
python -m core.synthetic_log_generator
# Outputs: data/sample_logs_100.json (~100 events with injected attacks)
```

### 8. Start the Backend

```bash
python main.py
```

Server starts at `http://0.0.0.0:8000`

### 9. Open the Dashboard

Open `dashboard.html` in your browser (no build step required).

---

## 📡 API Reference

### `POST /analyze`

Accepts flexible JSON input formats. All of the following are valid:

```json
// Format 1: Direct list
[{"user_id": "user_01", "event_type": "login_failed", ...}]

// Format 2: Wrapped list
{"logs": [{"user_id": "user_01", ...}]}

// Format 3: Single object
{"user_id": "user_01", "event_type": "login_success", ...}
```

**Response:**
```json
{
  "status": "success",
  "total_logs": 99230,
  "vectors_used": 99230,
  "total_incidents": 8,
  "incidents": [
    {
      "incident_id": 1,
      "user_id": "user_042",
      "correlation_strength": 0.7821,
      "avg_anomaly_score": 0.8234,
      "fidelity_score": 0.7812,
      "severity": "High",
      "event_count": 5
    }
  ]
}
```

### `GET /incidents`

Returns all incidents from the last `/analyze` run.

### `GET /playbook/{incident_id}`

Triggers Mistral LLM and returns the formatted incident response plan.

```json
{
  "incident_id": 1,
  "playbook": "=== INCIDENT RESPONSE PLAN ===\n\nSeverity: High\n\n1. Containment:\n- ..."
}
```

### `GET /stats`

Returns aggregate statistics:

```json
{
  "total_incidents": 8,
  "severity_breakdown": {"High": 3, "Medium": 4, "Low": 1},
  "avg_fidelity": 0.6834,
  "avg_correlation": 0.7102
}
```

---

## 📊 Sample End-to-End Output

### Input: 99,230 Logs

```
🐛 Debug: Received payload of type list
🐛 Debug: Normalized to 99230 logs
🚀 Fetching vectors from Elasticsearch...
📊 Logs: 99230 | Vectors: 99230
✅ ES vectors match events exactly — using ES vectors
🔍 Total users: 10
🔎 User user_3: seq_len=12340, avg_anomaly=0.6120
⚠️ Fallback incident created for user user_3
🚨 Total incidents detected: 8
```

### Incident Object

```json
{
  "incident_id": 2,
  "user_id": "user_847",
  "correlation_strength": 0.8302,
  "avg_anomaly_score": 0.9121,
  "fidelity_score": 0.8102,
  "severity": "High",
  "event_count": 4,
  "event_sequence": [
    "login_failed",
    "login_failed",
    "login_failed",
    "privilege_escalation"
  ]
}
```

### Fidelity Score Breakdown

```
fidelity = (0.5 × 0.9121)         # anomaly
         + (0.3 × 0.8302)         # correlation
         + (0.2 × 0.85)           # rule severity (privilege_escalation → 0.85)
         = 0.4561 + 0.2491 + 0.17
         = 0.8752   → Severity: "High"
```

---

## 💡 Future Improvements

### 1. Graph-Based Correlation (GraphRAG)
Model the entire log dataset as a directed graph where nodes are users/IPs/resources and edges are event-type transitions. Use Graph Neural Networks or GraphRAG to identify multi-hop attack chains that span across users — useful for detecting coordinated insider threats and lateral movement.

### 2. Real-Time Streaming (Apache Kafka)
Replace batch JSON ingestion with a Kafka consumer that processes events in a sliding window. Each event triggers incremental sequence updates, enabling sub-second incident detection instead of end-of-batch.

### 3. Risk-Based Alerting Prioritization
Add a dynamic alert queue that weighs incident fidelity score, asset criticality (which resources are involved), and analyst workload — so the most actionable incidents surface first, reducing alert fatigue.

### 4. Domain-Specific LLM Fine-Tuning
Fine-tune Mistral or Phi-3 on historical banking SOC runbooks and past incident reports to generate playbooks that are semantically calibrated to the org's actual response procedures, rather than general-purpose advice.

### 5. MITRE ATT&CK Mapping
Automatically tag detected incidents with corresponding MITRE ATT&CK technique IDs (T1110 — Brute Force, T1548 — Privilege Escalation, T1657 — Financial Theft) for standardized threat reporting.

### 6. Feedback Loop / Active Learning
Let analysts mark incident classifications as correct/incorrect and feed this signal back to retrain the Isolation Forest contamination threshold and pattern weights dynamically — closing the human-in-the-loop gap over time.

### 7. Multi-Tenant Isolation
Add organization-level namespacing in Elasticsearch indices and API authentication (JWT/API key) to support multiple bank clients on a shared infrastructure securely.

---

## 📄 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

## 🙋‍♂️ Author

**Ayush Gade**
Built as a production-grade demonstration of applied ML, SIEM architecture, and autonomous AI systems in cybersecurity.

---

<div align="center">

**If ACIRA helped you, please ⭐ the repository.**

*ACIRA — Because every second of undetected threat costs more than the entire system.*

</div>
