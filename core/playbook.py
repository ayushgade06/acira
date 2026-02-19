import subprocess
import json
from core.scoring import compute_fidelity_score


def generate_playbook(incident):

    fidelity, severity = compute_fidelity_score(incident)
    
    incident_summary = {
        "incident_id": incident.incident_id,
        "user_id": incident.user_id,
        "ip_address": incident.events[0].ip_address if incident.events else "Unknown",
        "avg_anomaly_score": incident.avg_anomaly_score,
        "correlation_strength": incident.correlation_strength,
        "fidelity_score": fidelity,
        "severity": severity,
        "event_types": [e.event_type for e in incident.events]
    }

    prompt = f"""
You are a senior banking SOC analyst.

Incident Data:
{json.dumps(incident_summary, indent=2)}

Rules:
- Base response ONLY on provided data.
- If privilege_escalation and db_access are present → treat as confirmed account compromise.
- If only login_failed + login_success → treat as suspected credential attack.
- Reference the specific user_id and ip_address.
- If severity is Critical → provide detailed technical actions.
- If severity is High → provide moderately detailed actions.
- Do NOT mention malware unless explicitly indicated.
- Do NOT say "lack of specific event types".
- Do NOT repeat generic filler text.

Return response strictly in this format:

=== INCIDENT RESPONSE PLAN ===

Severity: {incident_summary["severity"]}

1. Containment:
- Bullet points only

2. Eradication:
- Bullet points only

3. Recovery:
- Bullet points only

4. Reporting:
- Bullet points only

Be precise. Be technical. Be banking-focused.
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
