import pandas as pd


def extract_features(events):

    data = []

    failed_login_counts = {}
    password_change_counts = {}

    for event in events:
        if event.event_type == "login_failed":
            failed_login_counts[event.user_id] = failed_login_counts.get(event.user_id, 0) + 1

        if event.event_type == "password_change":
            password_change_counts[event.user_id] = password_change_counts.get(event.user_id, 0) + 1

    for event in events:

        login_hour = event.timestamp.hour
        odd_hour_flag = 1 if login_hour < 6 or login_hour > 22 else 0

        failed_count = failed_login_counts.get(event.user_id, 0)
        password_change_flag = 1 if event.event_type == "password_change" else 0
        transaction_flag = 1 if event.event_type == "transaction_initiated" else 0

        sensitive_access_flag = 1 if event.resource_accessed and "customer" in event.resource_accessed else 0
        privilege_flag = 1 if event.event_type == "privilege_escalation" else 0

        suspicious_ip_flag = 1 if not event.source_ip_address.startswith("192.") else 0

        high_threat_intel_flag = 1 if event.threat_intel_score and event.threat_intel_score > 70 else 0

        foreign_geo_flag = 0
        if event.geo and event.geo.get("country_name"):
            foreign_geo_flag = 1 if event.geo["country_name"] != "India" else 0

        data.append([
            login_hour,
            odd_hour_flag,
            failed_count,
            sensitive_access_flag,
            privilege_flag,
            suspicious_ip_flag,
            high_threat_intel_flag,
            foreign_geo_flag,
            password_change_flag,
            transaction_flag
        ])

    df = pd.DataFrame(data, columns=[
        "login_hour",
        "odd_hour_flag",
        "failed_login_count",
        "sensitive_access_flag",
        "privilege_escalation_flag",
        "suspicious_ip_flag",
        "high_threat_intel_flag",
        "foreign_geo_flag",
        "password_change_flag",
        "transaction_flag"
    ])

    return df


if __name__ == "__main__":
    from core.ingestion import load_logs

    logs = load_logs()
    df = extract_features(logs)

    print(df.head())
    print("\nFeature shape:", df.shape)
