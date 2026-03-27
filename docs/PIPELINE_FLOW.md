# ACIRA — Pipeline Flow Documentation

> **Scope:** This document describes the **exact current implementation** of the ACIRA pipeline as it exists in the codebase. It covers every stage, every data transformation, every function call, and every known limitation — with no redesign or future-state speculation.

---

## Table of Contents

1. [High-Level Overview](#1-high-level-overview)
2. [Architecture Diagram](#2-architecture-diagram)
3. [Step-by-Step Stage Breakdown](#3-step-by-step-stage-breakdown)
   - [Stage 1 — Log Upload (UI → Backend)](#stage-1--log-upload-ui--backend)
   - [Stage 2 — Log Ingestion & Parsing](#stage-2--log-ingestion--parsing)
   - [Stage 3 — Feature Engineering](#stage-3--feature-engineering)
   - [Stage 4 — Elasticsearch Vector Retrieval](#stage-4--elasticsearch-vector-retrieval)
   - [Stage 5 — Anomaly Detection](#stage-5--anomaly-detection)
   - [Stage 6 — Correlation Engine](#stage-6--correlation-engine)
   - [Stage 7 — Fidelity Scoring](#stage-7--fidelity-scoring)
   - [Stage 8 — Playbook Generation](#stage-8--playbook-generation)
   - [Stage 9 — Dashboard Rendering](#stage-9--dashboard-rendering)
4. [Data Flow Trace — One Log Through the Entire System](#4-data-flow-trace--one-log-through-the-entire-system)
5. [Current Limitations & Reality](#5-current-limitations--reality)
6. [Design Philosophy](#6-design-philosophy)

---

## 1. High-Level Overview

The ACIRA pipeline is a **batch-processing, hybrid SIEM** that runs synchronously from end to end each time the user uploads a JSON log file. There is no persistent state between runs — each `/analyze` call re-runs the entire pipeline from scratch.

```
User uploads JSON file via dashboard
        ↓
FastAPI /analyze endpoint receives raw JSON payload
        ↓
Payload normalized (list / dict / single object → List[LogInput])
        ↓
LogInput objects validated by Pydantic, then converted to LogEvent objects
        ↓
Events sorted chronologically by timestamp
        ↓
Feature Engineering: extract_features(events) → feature_df (n×10 DataFrame)
        ↓
Elasticsearch: fetch_vectors() attempted (up to 100,000 rows)
  → If vector count == event count: use ES vectors as feature matrix
  → If mismatch or ES failure: fall back to feature_df
        ↓
Anomaly Detection: IForest trains on feature matrix, scores every event [0.0–1.0]
        ↓
Correlation Engine: group by user_id → sort → scan sequences → detect patterns → Incident objects
        ↓
Fidelity Scoring: weighted formula → fidelity score + severity label per incident
        ↓
Incidents stored in global incidents_store
        ↓
Response returned to dashboard: incident list + counts
        ↓
User clicks "Generate Playbook" → /playbook/{id} → Mistral LLM via Ollama → formatted SOC plan
```

---

## 2. Architecture Diagram

```
┌─────────────────────────────────────────────┐
│              ACIRA PIPELINE                 │
│                                             │
│  ┌──────────────────────────────────────┐   │
│  │         dashboard.html               │   │
│  │  FileInput → fetch POST /analyze     │   │
│  └─────────────┬────────────────────────┘   │
│                │ raw JSON (list/dict)        │
│  ┌─────────────▼────────────────────────┐   │
│  │       main.py  /analyze              │   │
│  │  Payload normalization               │   │
│  │  Pydantic validation (LogInput)      │   │
│  │  LogEvent construction               │   │
│  └──────┬────────────────┬─────────────┘   │
│         │                │                  │
│  ┌──────▼──────┐  ┌──────▼──────────────┐  │
│  │ ingestion.py│  │feature_engineering.py│  │
│  │  LogEvent   │  │ extract_features()   │  │
│  │  (typed)    │  │ → DataFrame (n×10)   │  │
│  └──────┬──────┘  └──────────────────────┘  │
│         │                │                  │
│         │         ┌──────▼──────────────┐   │
│         │         │  vector_loader.py   │   │
│         │         │  fetch_vectors()    │   │
│         │         │  Elasticsearch      │   │
│         │         │  acira_vectors idx  │   │
│         │         └──────┬──────────────┘   │
│         │                │ (or fallback)    │
│         │         ┌──────▼──────────────┐   │
│         │         │    anomaly.py       │   │
│         │         │  IForest train+     │   │
│         └─────────►  score per event    │   │
│                   │  [0.0 – 1.0]        │   │
│                   └──────┬──────────────┘   │
│                          │                  │
│                   ┌──────▼──────────────┐   │
│                   │  correlation.py     │   │
│                   │  group by user_id   │   │
│                   │  sequence scanning  │   │
│                   │  → Incident objects │   │
│                   └──────┬──────────────┘   │
│                          │                  │
│                   ┌──────▼──────────────┐   │
│                   │    scoring.py       │   │
│                   │  fidelity score     │   │
│                   │  severity label     │   │
│                   └──────┬──────────────┘   │
│                          │                  │
│                   ┌──────▼──────────────┐   │
│                   │    playbook.py      │   │
│                   │  Mistral (Ollama)   │   │
│                   │  SOC response plan  │   │
│                   └──────┬──────────────┘   │
│                          │                  │
│                   ┌──────▼──────────────┐   │
│                   │   dashboard.html    │   │
│                   │  Chart.js + table   │   │
│                   └─────────────────────┘   │
└─────────────────────────────────────────────┘
```

---

## 3. Step-by-Step Stage Breakdown

---

### Stage 1 — Log Upload (UI → Backend)

**File:** `dashboard.html` → `main.py`

**What happens:**

The user selects a `.json` file via the file picker in `dashboard.html`. On clicking "Analyze Security Logs", the `uploadFile()` JavaScript function:

1. Reads the file contents using the browser's `File.text()` API
2. Parses it with `JSON.parse()` — at this point it may be a `[]` list, `{}` object, or `{"logs": [...]}` wrapper
3. Sends the parsed object directly as the `fetch` body with `Content-Type: application/json`

```javascript
// dashboard.html — uploadFile()
const text = await file.text();
const logs = JSON.parse(text);

const response = await fetch(`${API_BASE}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(logs)
});
```

**FastAPI receives the payload and normalizes it:**

```python
# main.py — analyze_logs()
def analyze_logs(payload: Union[Dict[str, Any], List[Dict[str, Any]]] = Body(...)):

    if isinstance(payload, list):
        raw_logs = payload                      # Format 1: direct list
    elif isinstance(payload, dict):
        if "logs" in payload:
            raw_logs = payload["logs"]          # Format 2: {"logs": [...]}
        else:
            raw_logs = [payload]                # Format 3: single object
```

**Pydantic validation:** Every item in `raw_logs` is converted to a `LogInput` object. If any required field (`user_id`, `source_ip_address`, `destination_ip_address`, `event_type`, `timestamp`, `resource_accessed`) is missing, a `422` error is returned with the exact field path.

```python
for i, item in enumerate(raw_logs):
    logs.append(LogInput(**item))
```

**Input:** Raw JSON (any format)
**Output:** `List[LogInput]` — Pydantic-validated, type-safe Python objects

---

### Stage 2 — Log Ingestion & Parsing

**File:** `core/ingestion.py`

**What happens:**

Each `LogInput` (Pydantic model) is converted to a `LogEvent` (plain Python class). This conversion:

- Parses `timestamp` from an ISO 8601 string to a `datetime` object — critical for chronological sorting and time-window arithmetic in correlation
- Sets `anomaly_score = None` — this will be assigned later by `anomaly.py`
- Stores `geo` as a dict (defaulting to `{}` if `None`)

```python
# main.py — inside analyze_logs()
events = [
    LogEvent(
        user_id=log.user_id,
        source_ip_address=log.source_ip_address,
        destination_ip_address=log.destination_ip_address,
        event_type=log.event_type,
        timestamp=log.timestamp,          # str → datetime in LogEvent.__init__
        resource_accessed=log.resource_accessed,
        dns_query=log.dns_query,
        file_path=log.file_path,
        file_hash=log.file_hash,
        username=log.username,
        hostname=log.hostname,
        geo=log.geo,
        threat_intel_score=log.threat_intel_score
    )
    for log in logs
]

events.sort(key=lambda x: x.timestamp)   # chronological sort
```

**Data masking** (`mask_value()` in `ingestion.py`) is applied only at `to_dict()` time — when an event is serialized for LLM input in `playbook.py`. The live `LogEvent` objects in memory carry unmasked data throughout the pipeline.

```python
def to_dict(self):
    return {
        "file_path":  mask_value(self.file_path),    # "C:\...\cmd.exe" → "***********"
        "file_hash":  mask_value(self.file_hash),
        "username":   mask_value(self.username),
        "hostname":   mask_value(self.hostname),
        # source_ip, destination_ip are NOT masked — needed for SOC containment
    }
```

**Note on `ingest_logs_to_es()` and `load_logs_from_es()`:** These functions in `ingestion.py` exist as standalone utilities for indexing and batch-fetching logs from the `acira_logs` Elasticsearch index. They are **not called by the `/analyze` endpoint** — the current live pipeline receives logs directly from the HTTP upload payload, not from ES. These functions are entry points for offline batch ingestion workflows.

**Input:** `List[LogInput]`
**Output:** `List[LogEvent]` sorted by `timestamp`

---

### Stage 3 — Feature Engineering

**File:** `core/feature_engineering.py`

**Function:** `extract_features(events) → pd.DataFrame`

**What happens:**

This stage converts the typed `LogEvent` objects into a numerical matrix that the Isolation Forest can consume. It performs two passes over `events`:

**Pass 1 — Aggregate user-level counters:**
```python
for event in events:
    if event.event_type == "login_failed":
        failed_login_counts[event.user_id] += 1
    if event.event_type == "password_change":
        password_change_counts[event.user_id] += 1
```

**Pass 2 — Extract per-event feature vector:**

| Feature | Computation |
|---------|-------------|
| `login_hour` | `event.timestamp.hour` — raw integer 0–23 |
| `odd_hour_flag` | `1` if hour < 6 or hour > 22, else `0` |
| `failed_login_count` | Total `login_failed` events for this user across entire dataset |
| `sensitive_access_flag` | `1` if `"customer"` appears in `resource_accessed` |
| `privilege_escalation_flag` | `1` if `event_type == "privilege_escalation"` |
| `suspicious_ip_flag` | `1` if source IP does **not** start with `"192."` |
| `high_threat_intel_flag` | `1` if `threat_intel_score > 70` |
| `foreign_geo_flag` | `1` if `geo["country_name"] != "India"` |
| `password_change_flag` | `1` if `event_type == "password_change"` |
| `transaction_flag` | `1` if `event_type == "transaction_initiated"` |

The result is a `pandas.DataFrame` of shape `(n_events, 10)` — exactly one row per `LogEvent`, in the same order.

**Key property:** `feature_df` is **always aligned 1:1 with `events`** — this is the safe ground truth matrix used as a fallback when ES vectors are unavailable or mismatched.

**Input:** `List[LogEvent]`
**Output:** `pd.DataFrame` shape `(n_events, 10)`

---

### Stage 4 — Elasticsearch Vector Retrieval

**File:** `core/vector_loader.py`

**Function:** `fetch_vectors() → List[dict]`

**What happens:**

The pipeline attempts to fetch pre-computed feature vectors from the `acira_vectors` Elasticsearch index. These vectors are uploaded ahead of time by `core/vector_upload.py`, which reads logs, runs `extract_features()`, and stores the resulting rows in ES.

```python
# vector_loader.py
def fetch_vectors():
    res = es.search(
        index="acira_vectors",
        body={"query": {"match_all": {}}},
        size=100_000   # ← must be large enough to cover all events
    )
    return [hit["_source"]["features"] for hit in res["hits"]["hits"]]
```

**Decision logic in `main.py`:**

```python
vectors = fetch_vectors()
vector_df = pd.DataFrame(vectors)

if len(vector_df) == len(events):
    # Use ES vectors — exact match confirmed
    pass
else:
    # Mismatch: fall back to locally computed feature_df
    vector_df = feature_df
```

**Why this decision matters:** ES vectors and `feature_df` represent the same information (both are outputs of `extract_features()`), but they may diverge if:
- ES was last indexed from a different log file than what was just uploaded
- The ES index is stale or partially populated
- The `size` parameter was previously too small (the original `1000` cap truncated everything)

The current implementation uses **count equality** as the alignment proxy. This is pragmatic but not guaranteed to be semantically correct — see [Limitations](#5-current-limitations--reality).

**Input:** Elasticsearch index `acira_vectors`
**Output:** `pd.DataFrame` (used as input to `anomaly.py`)

---

### Stage 5 — Anomaly Detection

**File:** `core/anomaly.py`

**Function:** `compute_anomaly_scores(events, feature_df) → List[LogEvent]`

**What happens:**

The feature matrix (`feature_df`) is passed to **Isolation Forest** from the `pyod` library.

```python
from pyod.models.iforest import IForest

model = IForest(contamination=0.2, random_state=42)
model.fit(feature_df)                            # trains on entire matrix

scores = model.decision_function(feature_df)    # raw anomaly scores (negative = anomalous)
```

**Score normalization:**

Raw Isolation Forest `decision_function` scores are unbounded and negative for anomalies. They are min-max normalized to `[0.0, 1.0]`:

```python
min_score = np.min(scores)
max_score = np.max(scores)
normalized = (scores - min_score) / (max_score - min_score + 1e-8)
```

- `0.0` = most normal event in this batch
- `1.0` = most anomalous event in this batch
- `1e-8` prevents division-by-zero when all scores are identical

**Score assignment:**

Normalized scores are assigned back to the `LogEvent` objects by index — this is why 1:1 alignment between `events` and `feature_df` is critical:

```python
for event, score in zip(events, normalized_scores):
    event.anomaly_score = round(float(score), 4)
```

**`contamination=0.2`** means the model's decision boundary is calibrated to expect ~20% anomalous points. This controls the internal threshold of the Isolation Forest — it does not directly filter events, but it influences the score distribution.

**Input:** `List[LogEvent]` + `pd.DataFrame (n×10)`
**Output:** `List[LogEvent]` with `anomaly_score` populated on every event

---

### Stage 6 — Correlation Engine

**File:** `core/correlation.py`

**Functions:** `detect_incidents(events)` + `Incident.calculate_metrics()`

**What happens:**

The anomaly-scored events are grouped and scanned for known multi-step attack patterns.

#### Step 6a — Group by User

```python
user_events = defaultdict(list)
for event in events:
    user_events[event.user_id].append(event)
```

Each user's events are then sorted by `timestamp`:
```python
logs.sort(key=lambda x: x.timestamp)
```

#### Step 6b — Sequence Scanning (Strict Pattern Match)

For each user, events are appended one by one to a growing `sequence`. After each append, two pattern conditions are evaluated:

**Pattern A — Brute Force → Privilege Escalation:**
```python
has_failed = any(e.event_type == "login_failed" for e in sequence)
has_priv   = any(e.event_type == "privilege_escalation" for e in sequence)
if has_failed and has_priv → INCIDENT
```

**Pattern B — Banking Fraud Chain:**
```python
has_pwd = any(e.event_type == "password_change" for e in sequence)
has_txn = any(e.event_type == "transaction_initiated" for e in sequence)
if has_pwd and has_txn → INCIDENT
```

When a pattern matches, an `Incident` is created from all events in the sequence up to that point, `incident_created = True` is set, and the scan for that user terminates (`break`).

#### Step 6c — Fallback Detection

If NO strict pattern was matched for a user but their sequence has ≥ 5 events with `avg_anomaly_score > 0.4`, a fallback incident is created using the first 5 events:

```python
if not incident_created and len(sequence) >= 5:
    scored = [e.anomaly_score for e in sequence if e.anomaly_score is not None]
    if scored:
        avg_anomaly = sum(scored) / len(scored)
        if avg_anomaly > 0.4:
            → FALLBACK INCIDENT (first 5 events of sequence)
```

#### Step 6d — `Incident.calculate_metrics()`

For every created incident, `calculate_metrics()` computes a `correlation_strength` score using:
- **Time decay score:** `exp(-duration / 3600)` — clustered events score higher
- **Resource criticality score:** Weighted by resource name (0.3–1.0)
- **IP risk score:** External IPs score higher; hashed IP randomness adds variance
- **Threat intel boost:** Mean of normalized `threat_intel_score` across events
- **Pattern bonus:** `+0.2` for brute-force chain, `+0.25` for fraud chain

These components are combined and passed through a logistic sigmoid to produce `correlation_strength` in range `[0.05, 0.99]`.

**Input:** `List[LogEvent]` (all with anomaly_score set)
**Output:** `List[Incident]`

---

### Stage 7 — Fidelity Scoring

**File:** `core/scoring.py`

**Function:** `compute_fidelity_score(incident) → (float, str)`

**What happens:**

Each incident is scored using a weighted formula:

```
fidelity = (0.5 × avg_anomaly_score)
         + (0.3 × correlation_strength)
         + (0.2 × rule_severity)
```

**Rule severity is determined by event type inspection:**

```python
event_types = [e.event_type for e in incident.events]

if "password_change" in event_types and "transaction_initiated" in event_types:
    rule_severity = 0.90    # fraud chain
elif "privilege_escalation" in event_types:
    rule_severity = 0.85    # admin compromise
elif event_types.count("login_failed") >= 3:
    rule_severity = 0.60    # brute force
elif "transaction_initiated" in event_types:
    rule_severity = 0.40    # financial suspicion
else:
    rule_severity = 0.20    # default anomaly
```

**Severity classification:**

```python
if fidelity > 0.85  → "High"
elif fidelity > 0.50 → "Medium"
else                → "Low"
```

The function returns a `(fidelity, severity)` tuple. In `main.py`, these are assigned to the incident:

```python
for incident in incidents:
    fidelity, severity = compute_fidelity_score(incident)
    incident.fidelity_score = fidelity
    incident.severity = severity
```

**Input:** `Incident` object
**Output:** `(float, str)` — fidelity score `[0.0–1.0]` and severity label

---

### Stage 8 — Playbook Generation

**File:** `core/playbook.py`

**Function:** `generate_playbook(incident) → str`

**Triggered by:** `GET /playbook/{incident_id}` — called separately from `/analyze`, only when the user clicks "Generate Playbook" in the dashboard.

**What happens:**

#### Step 8a — Re-score the Incident

```python
fidelity, severity = compute_fidelity_score(incident)
```

This re-runs the scoring logic on demand. It does not modify the stored incident.

#### Step 8b — Build Masked Incident Summary

The incident is serialized to a dict using `e.to_dict()` on each event. At this point, `mask_value()` is applied — `file_path`, `file_hash`, `username`, and `hostname` become asterisks. Source/destination IPs are preserved.

```python
incident_summary = {
    "incident_id": incident.incident_id,
    "user_id": incident.user_id,
    "source_ip_address": source_ip,
    "destination_ip_address": destination_ip,
    "avg_anomaly_score": incident.avg_anomaly_score,
    "fidelity_score": fidelity,
    "severity": severity,
    "event_types": [e.event_type for e in incident.events],
    "events": events_for_llm     # masked via to_dict()
}
```

#### Step 8c — Prompt Construction

A structured SOC-analyst prompt is built with:
- **Role priming:** "You are a senior banking SOC analyst"
- **Grounded data:** Full incident summary JSON embedded verbatim
- **Hard constraints:** "Base response ONLY on provided data. Do NOT hallucinate additional events."
- **Conditional depth:** "If severity is Critical → detailed technical actions"
- **Rigid output schema:** Forces exact 4-section format

#### Step 8d — Ollama Subprocess Call

```python
result = subprocess.run(
    ["ollama", "run", "mistral"],
    input=prompt,
    capture_output=True,
    text=True,
    encoding="utf-8",
    errors="ignore"
)
return result.stdout.strip()
```

Mistral is invoked as a subprocess — the model runs locally via Ollama. The call is **blocking and synchronous** — the `/playbook/{id}` endpoint will not return until the LLM finishes generating.

**Expected output format:**
```
=== INCIDENT RESPONSE PLAN ===
Severity: High

1. Containment:
- [action bullets]

2. Eradication:
- [action bullets]

3. Recovery:
- [action bullets]

4. Reporting:
- [action bullets]
```

**Input:** `Incident` object (from `incidents_store`)
**Output:** `str` — formatted SOC response plan

---

### Stage 9 — Dashboard Rendering

**File:** `dashboard.html`

**What happens:**

After `/analyze` returns, the dashboard:

1. Calls `renderIncidents(data.incidents)` to populate the incidents table with badge-colored severity labels
2. Calls `updateStats()` → fetches `/stats` → updates the 4 stat cards and re-draws the Chart.js doughnut chart
3. Shows a success/failure alert with total incident count

When the user clicks "Generate Playbook" for any row:

1. `generatePlaybook(incident_id)` is called
2. A shimmer skeleton loader appears in the playbook panel
3. `GET /playbook/{id}` is fetched — this blocks while Ollama runs
4. Response text is injected as `<pre>` content in the playbook panel
5. If the fullscreen modal is open, it is also updated

**All dashboard state is ephemeral** — refreshing the page or uploading a new file replaces all previous results.

---

## 4. Data Flow Trace — One Log Through the Entire System

Let's trace a single malicious event from raw JSON to playbook:

### Raw Input (in uploaded JSON file)
```json
{
  "user_id": "user_847",
  "source_ip_address": "78.43.201.12",
  "destination_ip_address": "10.0.0.5",
  "event_type": "privilege_escalation",
  "timestamp": "2026-02-17T03:14:59",
  "resource_accessed": "core_banking_admin_panel",
  "dns_query": "unknown-domain.net",
  "file_path": "C:\\Windows\\System32\\cmd.exe",
  "file_hash": "zzzzyyyyxxxx1111",
  "username": "vikram.mehta",
  "hostname": "SWIFT-GW-01",
  "geo": { "country_name": "Russia" },
  "threat_intel_score": 94
}
```

### Stage 1 — Pydantic Validation
```python
LogInput(
  user_id="user_847",
  source_ip_address="78.43.201.12",
  event_type="privilege_escalation",
  timestamp="2026-02-17T03:14:59",
  resource_accessed="core_banking_admin_panel",
  threat_intel_score=94,
  geo={"country_name": "Russia"},
  ...
)
```

### Stage 2 — LogEvent Construction
```python
LogEvent(
  user_id="user_847",
  timestamp=datetime(2026, 2, 17, 3, 14, 59),   # str → datetime
  event_type="privilege_escalation",
  source_ip_address="78.43.201.12",
  threat_intel_score=94,
  anomaly_score=None                              # ← not scored yet
)
```

### Stage 3 — Feature Vector
```python
[
  3,    # login_hour (3 AM)
  1,    # odd_hour_flag (hour < 6)
  3,    # failed_login_count (user_847 had 3 login_failed events before this)
  0,    # sensitive_access_flag ("customer" not in "core_banking_admin_panel")
  1,    # privilege_escalation_flag ← HIGH SIGNAL
  1,    # suspicious_ip_flag (78.x is not 192.x)
  1,    # high_threat_intel_flag (94 > 70)
  1,    # foreign_geo_flag (Russia != India)
  0,    # password_change_flag
  0     # transaction_flag
]
```

This row becomes row `i` in `feature_df`.

### Stage 4 — Anomaly Score
Isolation Forest scores this vector as highly anomalous (multiple flags active simultaneously). After normalization:

```python
event.anomaly_score = 0.9341
```

### Stage 5 — Correlation
`user_847`'s sequence at the moment this event is appended:
```
[login_failed, login_failed, login_failed, privilege_escalation]
```

Pattern A fires: `has_failed=True AND has_priv=True` → **INCIDENT CREATED**

### Stage 6 — Incident Object
```python
Incident(
  incident_id=2,
  user_id="user_847",
  events=[e1_login_failed, e2_login_failed, e3_login_failed, e4_privilege_escalation],
  avg_anomaly_score=0.8812,      # mean across 4 events
  correlation_strength=0.8302    # calculated by calculate_metrics()
)
```

### Stage 7 — Fidelity Score
```
rule_severity = 0.85             # privilege_escalation present
fidelity = (0.5 × 0.8812)
         + (0.3 × 0.8302)
         + (0.2 × 0.85)
         = 0.4406 + 0.2491 + 0.17
         = 0.8597    → severity = "High"
```

### Stage 8 — Playbook
Masked event data is sent to Mistral. `file_path`, `file_hash`, `username`, `hostname` are replaced with `*` strings. The prompt references `user_847` and `78.43.201.12` explicitly. Mistral returns:

```
=== INCIDENT RESPONSE PLAN ===
Severity: High

1. Containment:
- Immediately suspend user_847's admin privileges across all banking systems
- Block source IP 78.43.201.12 at the perimeter firewall
...
```

### Stage 9 — Dashboard
The incident row appears in the table with severity badge `HIGH` (red). Fidelity `0.8597` and anomaly score `0.8812` are displayed. Clicking "Generate Plan" triggers the playbook display.

---

## 5. Current Limitations & Reality

### Limitation 1 — ES Vector Index May Not Exist or Be Stale

**What:** `fetch_vectors()` queries `acira_vectors` — an index that must be pre-populated by running `vector_upload.py` separately. If the index is empty, ES returns 0 vectors and the pipeline falls back to `feature_df`.

**Why it matters:** If `acira_vectors` was last populated from a different dataset than the currently uploaded logs, and if by coincidence the row counts match, the pipeline will **silently use misaligned vectors** — the anomaly score for event `i` will be computed from a different event's feature vector.

**Current mitigation:** The `len(vector_df) == len(events)` check prevents the most common misalignment (count mismatch), but does not guarantee semantic alignment.

---

### Limitation 2 — `load_logs_from_es()` Has a Hard `size=1000` Cap

**What:** `ingestion.py`'s `load_logs_from_es()` only retrieves 1,000 documents from Elasticsearch.

**Why it matters:** This function is used in standalone scripts (`anomaly.py __main__`, `playbook.py __main__`), not in the live API pipeline. However, if someone calls it for batch offline processing with large datasets, it silently truncates.

---

### Limitation 3 — Correlation Uses Global Sequence, Not Time-Windowed

**What:** The sequence scan accumulates **all** events for a user in order, regardless of gaps. A `login_failed` at 00:00 and a `privilege_escalation` at 23:59 would still form an incident.

**Why it matters:** In a real SIEM, correlation windows are typically 5–60 minutes. The current implementation could produce false positives for users who simply had unrelated events in the same batch.

---

### Limitation 4 — Fixed `contamination=0.2` Threshold

**What:** The Isolation Forest's contamination parameter is hardcoded to `0.2`.

**Why it matters:** If the actual anomaly rate in the uploaded dataset is significantly different (e.g., a very clean batch = 1% anomalies, or a very dirty batch = 40% anomalies), the normalized scores will still span `[0.0, 1.0]` but the model's internal decision boundary will be miscalibrated. This can inflate or suppress anomaly scores for specific batches.

---

### Limitation 5 — No Real-Time Streaming

**What:** The entire pipeline runs synchronously per `/analyze` POST call. There is no Kafka consumer, no sliding window, no incremental state.

**Why it matters:** ACIRA cannot react to an in-progress attack. All detection is retrospective — it analyzes a complete batch of logs that have already been collected.

---

### Limitation 6 — `incidents_store` is a Global In-Memory List

**What:**
```python
# main.py
incidents_store = []
```

**Why it matters:** This list is shared across all concurrent requests and is overwritten on every `/analyze` call. In a multi-user or concurrent request scenario, a new analysis wipes the previous results. The `/incidents` and `/playbook/{id}` endpoints only see the most recent analysis run.

---

### Limitation 7 — Ollama Subprocess is Synchronous and Unbounded

**What:** The `generate_playbook()` function spawns `ollama run mistral` as a blocking subprocess with no timeout.

**Why it matters:** If Ollama is slow (CPU-only inference on large incidents), the `/playbook/{id}` endpoint can take 30–120 seconds to return. The dashboard JavaScript has no timeout — it will wait indefinitely.

---

## 6. Design Philosophy

### Hybrid SIEM (ML + Rules + Correlation)

ACIRA is not a pure ML system, nor a pure rule-based system. It is a **three-layer hybrid**:

| Layer | Technique | Role |
|-------|-----------|------|
| Statistical | Isolation Forest | Detects individually abnormal events — novel, data-driven |
| Rule-based | Pattern matching on `event_type` | Detects known attack sequences — fast, deterministic, explainable |
| Correlative | Multi-event sequence grouping | Provides narrative context — converts alerts into incidents |

Each layer compensates for the weaknesses of the others:
- ML catches statistical outliers that rules miss
- Rules catch known patterns that ML might normalize away
- Correlation prevents both from acting on individual events out of context

### Modular Pipeline

Each module (`ingestion`, `feature_engineering`, `anomaly`, `correlation`, `scoring`, `playbook`) is a standalone Python file with no circular imports. Each can be run independently via its `if __name__ == "__main__"` block. This means:
- Individual stages can be tested, benchmarked, or replaced without touching the rest
- The FastAPI orchestrator (`main.py`) is purely a coordinator — it imports and sequences modules but adds no domain logic itself

### Batch Processing

ACIRA processes logs as complete batches. All feature vectors are computed together (so `failed_login_count` reflects the full dataset), the Isolation Forest trains on the whole batch, and correlation has access to every event before scoring begins. This approach trades **latency** for **completeness** — the model always sees the full behavioral context before making any decision.

---

*Last updated: 2026-03-27 | ACIRA v2.1*
