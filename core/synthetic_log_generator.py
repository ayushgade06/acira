import random
import json
from datetime import datetime, timedelta


real_usernames = [
    "rahul.sharma",
    "ananya.patel",
    "vikram.mehta",
    "priya.nair",
    "arjun.reddy"
]

real_hostnames = [
    "CORP-LAPTOP-01",
    "FINANCE-WS-22",
    "HR-TERMINAL-07",
    "SWIFT-GW-01",
    "ATM-SERVER-12"
]

countries = ["India", "Germany", "Singapore", "Russia"]

TOTAL_LOGS = 100_000
NORMAL_RATIO = 0.98  # 98% normal traffic


def generate_normal_event(user_id, timestamp):
    username = random.choice(real_usernames)
    hostname = random.choice(real_hostnames)

    return {
        "user_id": user_id,
        "source_ip_address": f"192.168.1.{random.randint(1,254)}",
        "destination_ip_address": "10.0.0.5",
        "event_type": random.choice(["login_success", "transaction_initiated"]),
        "timestamp": timestamp.isoformat(),
        "resource_accessed": "customer_financial_db",
        "dns_query": "secure.bank.internal",
        "file_path": "C:\\Program Files\\BankApp\\client.exe",
        "file_hash": "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
        "username": username,
        "hostname": hostname,
        "geo": {"country_name": "India"},
        "threat_intel_score": random.randint(5, 40)
    }


def generate_fraud_sequence(base_time):
    """password_change → transaction_initiated"""
    ip = f"{random.randint(50,200)}.{random.randint(1,200)}.{random.randint(1,200)}.{random.randint(1,254)}"
    username = random.choice(real_usernames)
    hostname = random.choice(real_hostnames)

    events = []

    events.append({
        "user_id": f"user_{random.randint(500,800)}",
        "source_ip_address": ip,
        "destination_ip_address": "10.0.0.5",
        "event_type": "password_change",
        "timestamp": base_time.isoformat(),
        "resource_accessed": "customer_financial_db",
        "dns_query": "malicious.ru",
        "file_path": "C:\\Temp\\evil.exe",
        "file_hash": "abcd1234efgh5678ijkl",
        "username": username,
        "hostname": hostname,
        "geo": {"country_name": random.choice(["Russia", "Germany"])},
        "threat_intel_score": random.randint(85, 100)
    })

    events.append({
        **events[0],
        "event_type": "transaction_initiated",
        "timestamp": (base_time + timedelta(minutes=3)).isoformat(),
        "threat_intel_score": random.randint(90, 100)
    })

    return events


def generate_bruteforce_sequence(base_time):
    """login_failed x3 → privilege_escalation"""
    ip = f"{random.randint(40,200)}.{random.randint(1,200)}.{random.randint(1,200)}.{random.randint(1,254)}"
    username = random.choice(real_usernames)
    hostname = random.choice(real_hostnames)

    user_id = f"user_{random.randint(800,999)}"
    events = []

    for i in range(3):
        events.append({
            "user_id": user_id,
            "source_ip_address": ip,
            "destination_ip_address": "10.0.0.5",
            "event_type": "login_failed",
            "timestamp": (base_time + timedelta(minutes=i)).isoformat(),
            "resource_accessed": "customer_financial_db",
            "dns_query": "unknown-domain.net",
            "file_path": None,
            "file_hash": None,
            "username": username,
            "hostname": hostname,
            "geo": {"country_name": random.choice(countries)},
            "threat_intel_score": random.randint(70, 90)
        })

    events.append({
        "user_id": user_id,
        "source_ip_address": ip,
        "destination_ip_address": "10.0.0.5",
        "event_type": "privilege_escalation",
        "timestamp": (base_time + timedelta(minutes=5)).isoformat(),
        "resource_accessed": "core_banking_admin_panel",
        "dns_query": "unknown-domain.net",
        "file_path": "C:\\Windows\\System32\\cmd.exe",
        "file_hash": "zzzzyyyyxxxx1111",
        "username": username,
        "hostname": hostname,
        "geo": {"country_name": random.choice(countries)},
        "threat_intel_score": random.randint(85, 100)
    })

    return events


def generate_logs():
    logs = []
    current_time = datetime(2026, 2, 17, 0, 0)

    normal_count = int(TOTAL_LOGS * NORMAL_RATIO)
    attack_count = TOTAL_LOGS - normal_count

    # -------------------------
    # Generate Normal Traffic
    # -------------------------
    for i in range(normal_count):
        user_id = f"user_{random.randint(1,400)}"
        logs.append(generate_normal_event(user_id, current_time))
        current_time += timedelta(seconds=random.randint(5, 30))

    # -------------------------
    # Inject Attack Sequences Randomly
    # -------------------------
    for _ in range(attack_count // 5):

        attack_time = current_time + timedelta(seconds=random.randint(10, 300))

        if random.random() < 0.5:
            logs.extend(generate_fraud_sequence(attack_time))
        else:
            logs.extend(generate_bruteforce_sequence(attack_time))

        current_time += timedelta(seconds=random.randint(20, 60))

    logs.sort(key=lambda x: x["timestamp"])
    return logs


if __name__ == "__main__":
    dataset = generate_logs()

    with open("data/sample_logs.json", "w") as f:
        json.dump(dataset, f)

    print(f"Generated {len(dataset)} intelligent EDR + SIEM log events successfully.")
