def compute_fidelity_score(incident):

    # -----------------------------
    # 1️⃣ Dynamic Rule Severity
    # -----------------------------
    event_types = [e.event_type for e in incident.events]

    rule_severity = 0.0

    # Critical multi-step fraud pattern
    if "password_change" in event_types and "transaction_initiated" in event_types:
        rule_severity = 0.9

    # Privilege escalation attack
    elif "privilege_escalation" in event_types:
        rule_severity = 0.85

    # Brute force pattern
    elif event_types.count("login_failed") >= 3:
        rule_severity = 0.6

    # Single suspicious activity
    elif "transaction_initiated" in event_types:
        rule_severity = 0.4

    # Default minor anomaly
    else:
        rule_severity = 0.2


    # -----------------------------
    # 2️⃣ Fidelity Calculation
    # -----------------------------
    fidelity = (
        0.5 * incident.avg_anomaly_score
        + 0.3 * incident.correlation_strength
        + 0.2 * rule_severity
    )

    fidelity = round(fidelity, 4)


    # -----------------------------
    # 3️⃣ Keep Your Original Bands
    # -----------------------------
    if fidelity > 0.85:
        severity = "High"
    elif fidelity > 0.5:
        severity = "Medium"
    else:
        severity = "Low"

    return fidelity, severity


# ----------------------------------
# Testing Block
# ----------------------------------
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
        incident = incidents[0]
        fidelity, severity = compute_fidelity_score(incident)

        print("Fidelity Score:", fidelity)
        print("Severity Level:", severity)
