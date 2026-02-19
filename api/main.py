from fastapi import FastAPI
from typing import List, Optional
from pydantic import BaseModel
from core.ingestion import load_logs, LogEvent
from core.feature_engineering import extract_features
from core.anomaly import compute_anomaly_scores
from core.correlation import detect_incidents
from core.scoring import compute_fidelity_score
from core.playbook import generate_playbook
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI(title="ACIRA - Autonomous Cyber Incident Response Agent")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

cached_incidents = []


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


@app.post("/analyze")
def analyze(log_data: Optional[List[LogInput]] = None):

    global cached_incidents

    if log_data:
        logs = [
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
            for log in log_data
        ]
        logs.sort(key=lambda x: x.timestamp)
    else:
        logs = load_logs()

    features = extract_features(logs)
    logs = compute_anomaly_scores(logs, features)
    incidents = detect_incidents(logs)

    enriched_incidents = []

    for incident in incidents:
        fidelity, severity = compute_fidelity_score(incident)
        incident_data = incident.to_dict()
        incident_data["fidelity_score"] = fidelity
        incident_data["severity"] = severity
        enriched_incidents.append(incident_data)

    cached_incidents = enriched_incidents

    return {
        "total_incidents": len(enriched_incidents),
        "incidents": enriched_incidents
    }


@app.get("/incidents")
def get_incidents():
    return cached_incidents


@app.get("/playbook/{incident_id}")
def get_playbook(incident_id: int):

    for incident in cached_incidents:
        if incident["incident_id"] == incident_id:

            from core.correlation import Incident
            from core.ingestion import LogEvent

            reconstructed_events = [
                LogEvent(
                    user_id=e["user_id"],
                    source_ip_address=e["source_ip_address"],
                    destination_ip_address=e["destination_ip_address"],
                    event_type=e["event_type"],
                    timestamp=e["timestamp"],
                    resource_accessed=e["resource_accessed"],
                    dns_query=e.get("dns_query"),
                    file_path=e.get("file_path"),
                    file_hash=e.get("file_hash"),
                    username=e.get("username"),
                    hostname=e.get("hostname"),
                    geo=e.get("geo"),
                    threat_intel_score=e.get("threat_intel_score")
                )
                for e in incident["events"]
            ]

            dummy_incident = Incident(
                incident_id=incident["incident_id"],
                user_id=incident["user_id"],
                events=reconstructed_events
            )

            dummy_incident.avg_anomaly_score = incident["avg_anomaly_score"]
            dummy_incident.correlation_strength = incident["correlation_strength"]

            playbook = generate_playbook(dummy_incident)

            return {
                "incident_id": incident_id,
                "playbook": playbook
            }

    return {"error": "Incident not found"}
