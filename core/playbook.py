import subprocess
import json
from core.scoring import compute_fidelity_score


def generate_playbook(incident):

    fidelity, severity = compute_fidelity_score(incident)

    if incident.events:
        first_event = incident.events[0]
        source_ip = first_event.source_ip_address
        destination_ip = first_event.destination_ip_address
    else:
        source_ip = "Unknown"
        destination_ip = "Unknown"

    # Use to_dict() (already masks only 4 required fields)
    events_for_llm = [e.to_dict() for e in incident.events]

    incident_summary = {
        "incident_id": incident.incident_id,
        "user_id": incident.user_id,
        "source_ip_address": source_ip,
        "destination_ip_address": destination_ip,
        "avg_anomaly_score": incident.avg_anomaly_score,
        "correlation_strength": incident.correlation_strength,
        "fidelity_score": fidelity,
        "severity": severity,
        "event_types": [e.event_type for e in incident.events],
        "events": events_for_llm
    }

    prompt = f"""
You are a senior banking SOC analyst.

Incident Data:
{json.dumps(incident_summary, indent=2)}

Rules:
- Base response ONLY on provided data.
- If privilege_escalation and db_access are present → treat as confirmed account compromise.
- If password_change followed by transaction_initiated → treat as potential account takeover fraud.
- Reference the specific user_id and source_ip_address.
- If severity is Critical → provide detailed technical actions.
- If severity is High → provide moderately detailed actions.
- Do NOT hallucinate additional events.
- Do NOT mention malware unless explicitly present in data.
- Be precise and banking-focused.

Return response strictly in this format:

=== INCIDENT RESPONSE PLAN ===

Severity: {severity}

1. Containment:
- Bullet points only

2. Eradication:
- Bullet points only

3. Recovery:
- Bullet points only

4. Reporting:
- Bullet points only
"""

    result = subprocess.run(
        ["ollama", "run", "mistral"],
        input=prompt,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore"
    )

    return result.stdout.strip()


if __name__ == "__main__":
    from core.ingestion import load_logs
    from core.feature_engineering import extract_features
    from core.anomaly import compute_anomaly_scores
    from core.correlation import detect_incidents

    logs = load_logs()
    features = extract_features(logs)
    logs = compute_anomaly_scores(logs, features)
    incidents = detect_incidents(logs)

    if incidents:
        playbook = generate_playbook(incidents[0])
        print("\nGenerated Playbook:\n")
        print(playbook)
