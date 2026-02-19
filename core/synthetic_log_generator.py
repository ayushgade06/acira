import random
import json
from datetime import datetime, timedelta


def generate_logs():

    logs = []
    base_time = datetime(2026, 2, 17, 9, 0)

    for i in range(1, 101):

        user_id = f"user_{i}"
        ip = f"192.168.1.{i}"

        logs.append({
            "user_id": user_id,
            "ip_address": ip,
            "event_type": "login_success",
            "timestamp": (base_time + timedelta(minutes=i)).isoformat(),
            "resource_accessed": "NA"
        })

        logs.append({
            "user_id": user_id,
            "ip_address": ip,
            "event_type": "file_access",
            "timestamp": (base_time + timedelta(minutes=i+2)).isoformat(),
            "resource_accessed": random.choice([
                "public_docs",
                "reports",
                "training_material",
                "internal_policy_docs"
            ])
        })

        if random.random() < 0.4:
            logs.append({
                "user_id": user_id,
                "ip_address": ip,
                "event_type": "db_access",
                "timestamp": (base_time + timedelta(minutes=i+4)).isoformat(),
                "resource_accessed": random.choice([
                    "employee_db",
                    "sales_db",
                    "analytics_db"
                ])
            })

    suspicious_users = ["user_23", "user_47", "user_88"]

    for su in suspicious_users:

        attack_ip = f"{random.randint(40,120)}.{random.randint(10,200)}.{random.randint(10,200)}.{random.randint(1,254)}"
        attack_time = datetime(2026, 2, 17, random.randint(1,4), random.randint(0,59))

        # Brute force attempts
        for j in range(3):
            logs.append({
                "user_id": su,
                "ip_address": attack_ip,
                "event_type": "login_failed",
                "timestamp": (attack_time + timedelta(minutes=j)).isoformat(),
                "resource_accessed": "NA"
            })

        # Successful login
        logs.append({
            "user_id": su,
            "ip_address": attack_ip,
            "event_type": "login_success",
            "timestamp": (attack_time + timedelta(minutes=3)).isoformat(),
            "resource_accessed": "NA"
        })

        # Sensitive DB access
        logs.append({
            "user_id": su,
            "ip_address": attack_ip,
            "event_type": "db_access",
            "timestamp": (attack_time + timedelta(minutes=4)).isoformat(),
            "resource_accessed": "customer_financial_db"
        })

        # Privilege escalation
        logs.append({
            "user_id": su,
            "ip_address": attack_ip,
            "event_type": "privilege_escalation",
            "timestamp": (attack_time + timedelta(minutes=6)).isoformat(),
            "resource_accessed": "core_banking_admin_panel"
        })

    # Sort chronologically
    logs.sort(key=lambda x: x["timestamp"])

    return logs


if __name__ == "__main__":

    dataset = generate_logs()

    with open("data/sample_logs.json", "w") as f:
        json.dump(dataset, f, indent=2)

    print(f"Generated {len(dataset)} log events successfully.")
