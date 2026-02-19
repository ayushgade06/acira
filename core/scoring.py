def compute_fidelity_score(incident):

    rule_severity = 1.0  

    fidelity = (
        0.5 * incident.avg_anomaly_score
        + 0.3 * incident.correlation_strength
        + 0.2 * rule_severity
    )

    fidelity = round(fidelity, 4)

    if fidelity > 0.85:
        severity = "Critical"
    elif fidelity > 0.5:
        severity = "Medium"
    else:
        severity = "Low"

    return fidelity, severity

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
