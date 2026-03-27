from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Union, Dict, Any, Optional
import uvicorn
import pandas as pd

# Core modules
from core.ingestion import LogEvent
from core.feature_engineering import extract_features
from core.anomaly import compute_anomaly_scores
from core.correlation import detect_incidents
from core.playbook import generate_playbook
from core.scoring import compute_fidelity_score
from core.vector_loader import fetch_vectors

# ----------------------------------------
# App Initialization
# ----------------------------------------

app = FastAPI(
    title="ACIRA - Autonomous Cyber Incident Response Agent",
    version="2.1",
    description="SIEM + UEBA + Vector DB + ML Pipeline"
)

# Enable CORS (frontend support)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global store
incidents_store = []

# ----------------------------------------
# Input Schema
# ----------------------------------------

class LogInput(BaseModel):
    user_id: str
    source_ip_address: str
    destination_ip_address: str
    event_type: str
    timestamp: str
    resource_accessed: str
    dns_query: Optional[str] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    geo: Optional[dict] = None
    threat_intel_score: Optional[int] = None

# ----------------------------------------
# Root Endpoint
# ----------------------------------------

@app.get("/")
def root():
    return {
        "message": "ACIRA - Autonomous Cyber Incident Response Agent",
        "status": "operational",
        "version": "2.1",
        "features": [
            "TSFresh Behavioral Modeling",
            "PCA Vector Compression",
            "Elasticsearch Vector DB",
            "Isolation Forest Anomaly Detection",
            "Incident Correlation Engine"
        ]
    }

# ----------------------------------------
# MAIN PIPELINE
# ----------------------------------------

@app.post("/analyze")
def analyze_logs(payload: Union[Dict[str, Any], List[Dict[str, Any]]] = Body(...)):
    """
    Full Pipeline:
    1. JSON → LogEvent
    2. Feature Engineering (fallback)
    3. Fetch PCA vectors from Elasticsearch
    4. Align data
    5. Anomaly Detection (Isolation Forest)
    6. Incident Correlation
    7. Fidelity Scoring
    """

    global incidents_store

    print(f"🐛 Debug: Received payload of type {type(payload).__name__}")

    # ----------------------------------------
    # Input Normalization
    # ----------------------------------------
    raw_logs = []
    if isinstance(payload, list):
        print(f"🐛 Debug: Interpreting as direct list")
        raw_logs = payload
    elif isinstance(payload, dict):
        if "logs" in payload and isinstance(payload["logs"], list):
            print(f"🐛 Debug: Interpreting as wrapped list")
            raw_logs = payload["logs"]
        else:
            print(f"🐛 Debug: Interpreting as single object")
            raw_logs = [payload]
    else:
        raise HTTPException(status_code=422, detail="Invalid request format. Expected a single log object, a list of logs, or a JSON object with a 'logs' key containing a list.")

    print(f"🐛 Debug: Normalized to {len(raw_logs)} logs")

    # ----------------------------------------
    # Validation & Parsing
    # ----------------------------------------
    logs: List[LogInput] = []
    for i, item in enumerate(raw_logs):
        if not isinstance(item, dict):
            raise HTTPException(status_code=422, detail=f"Log item at index {i} must be a JSON object (dictionary).")
        try:
            logs.append(LogInput(**item))
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"Validation failed for log item at index {i}. Required fields may be missing or invalid. Details: {str(e)}")

    try:
        # ----------------------------------------
        # Step 1: Convert logs → objects
        # ----------------------------------------
        events = [
            LogEvent(
                user_id=log.user_id,
                source_ip_address=log.source_ip_address,
                destination_ip_address=log.destination_ip_address,
                event_type=log.event_type,
                timestamp=log.timestamp,
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

        events.sort(key=lambda x: x.timestamp)

        # ----------------------------------------
        # Step 2: Feature Engineering (backup)
        # ----------------------------------------
        feature_df = extract_features(events)

        # ----------------------------------------
        # Step 3: Fetch vectors from ES
        # ----------------------------------------
        try:
            print("🚀 Fetching vectors from Elasticsearch...")
            vectors = fetch_vectors()
            vector_df = pd.DataFrame(vectors)

            print(f"📊 Logs: {len(events)} | Vectors: {len(vector_df)}")

            # ✅ FIX Bug 3: only use ES vectors if they cover ALL events.
            # Partial coverage means different rows → misaligned anomaly scores.
            if len(vector_df) == len(events):
                print(f"✅ ES vectors match events exactly — using ES vectors")
            else:
                print(f"⚠️ ES vector count ({len(vector_df)}) != events ({len(events)}) → falling back to feature_df")
                vector_df = feature_df  # always 1:1 with events

        except Exception as e:
            print(f"⚠️ ES failed → using feature engineering instead: {e}")
            vector_df = feature_df

        # ----------------------------------------
        # Step 4: Anomaly Detection
        # ----------------------------------------
        events = compute_anomaly_scores(events, vector_df)

        # ----------------------------------------
        # Step 5: Incident Detection
        # ----------------------------------------
        incidents = detect_incidents(events)

        # ----------------------------------------
        # Step 6: Fidelity Scoring
        # ----------------------------------------
        for incident in incidents:
            fidelity, severity = compute_fidelity_score(incident)
            incident.fidelity_score = fidelity
            incident.severity = severity

        # Store globally
        incidents_store = incidents

        # ----------------------------------------
        # Response
        # ----------------------------------------
        return {
            "status": "success",
            "total_logs": len(logs),
            "vectors_used": len(vector_df),
            "total_incidents": len(incidents),
            "incidents": [
                {
                    "incident_id": inc.incident_id,
                    "user_id": inc.user_id,
                    "correlation_strength": inc.correlation_strength,
                    "avg_anomaly_score": inc.avg_anomaly_score,
                    "fidelity_score": inc.fidelity_score,
                    "severity": inc.severity,
                    "event_count": len(inc.events)
                }
                for inc in incidents
            ]
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ----------------------------------------
# INCIDENTS ENDPOINT
# ----------------------------------------

@app.get("/incidents")
def get_incidents():
    return [
        {
            "incident_id": inc.incident_id,
            "user_id": inc.user_id,
            "correlation_strength": inc.correlation_strength,
            "fidelity_score": inc.fidelity_score,
            "severity": inc.severity,
            "avg_anomaly_score": inc.avg_anomaly_score
        }
        for inc in incidents_store
    ]

# ----------------------------------------
# PLAYBOOK GENERATION
# ----------------------------------------

@app.get("/playbook/{incident_id}")
def get_playbook(incident_id: int):
    try:
        incident = next(
            (inc for inc in incidents_store if inc.incident_id == incident_id),
            None
        )

        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        playbook = generate_playbook(incident)

        return {
            "incident_id": incident_id,
            "playbook": playbook
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ----------------------------------------
# SYSTEM STATS
# ----------------------------------------

@app.get("/stats")
def get_stats():
    if not incidents_store:
        return {
            "total_incidents": 0,
            "severity_breakdown": {},
            "avg_fidelity": 0,
            "avg_correlation": 0
        }

    severity_count = {}
    for inc in incidents_store:
        severity_count[inc.severity] = severity_count.get(inc.severity, 0) + 1

    avg_fidelity = sum(inc.fidelity_score for inc in incidents_store) / len(incidents_store)
    avg_correlation = sum(inc.correlation_strength for inc in incidents_store) / len(incidents_store)

    return {
        "total_incidents": len(incidents_store),
        "severity_breakdown": severity_count,
        "avg_fidelity": round(avg_fidelity, 4),
        "avg_correlation": round(avg_correlation, 4)
    }

# ----------------------------------------
# RUN SERVER
# ----------------------------------------

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)