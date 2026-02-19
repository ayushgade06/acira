import pandas as pd


def extract_features(events):

    data = []

    failed_login_counts = {}
    for event in events:
        if event.event_type == "login_failed":
            failed_login_counts[event.user_id] = failed_login_counts.get(event.user_id, 0) + 1

    for event in events:
        login_hour = event.timestamp.hour

        odd_hour_flag = 1 if login_hour < 6 or login_hour > 22 else 0

        failed_count = failed_login_counts.get(event.user_id, 0)

        sensitive_access_flag = 1 if "customer" in event.resource_accessed else 0

        privilege_flag = 1 if event.event_type == "privilege_escalation" else 0

        suspicious_ip_flag = 1 if not event.ip_address.startswith("192.") else 0

        data.append([
            login_hour,
            odd_hour_flag,
            failed_count,
            sensitive_access_flag,
            privilege_flag,
            suspicious_ip_flag
        ])

    df = pd.DataFrame(data, columns=[
        "login_hour",
        "odd_hour_flag",
        "failed_login_count",
        "sensitive_access_flag",
        "privilege_escalation_flag",
        "suspicious_ip_flag"
    ])

    return df


if __name__ == "__main__":
    from core.ingestion import load_logs

    logs = load_logs()
    df = extract_features(logs)

    print(df.head())
    print("\nFeature shape:", df.shape)
