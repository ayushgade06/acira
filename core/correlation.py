from collections import defaultdict
import math
import hashlib


class Incident:
    def __init__(self, incident_id, user_id, events):
        self.incident_id = incident_id
        self.user_id = user_id
        self.events = events
        self.correlation_strength = 0
        self.avg_anomaly_score = 0

    def calculate_metrics(self):

        self.avg_anomaly_score = round(
            sum(e.anomaly_score for e in self.events if e.anomaly_score is not None)
            / len(self.events),
            4
        )

        timestamps = [e.timestamp.timestamp() for e in self.events]
        total_duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0
        time_score = math.exp(-total_duration / 3600)

        # Resource Criticality
        critical_weights = {
            "customer_financial_db": 0.9,
            "core_banking_admin_panel": 1.0,
            "swift_gateway": 1.0,
            "employee_db": 0.7,
            "analytics_db": 0.6
        }

        resource_score = sum(
            critical_weights.get(e.resource_accessed, 0.3)
            for e in self.events
        ) / len(self.events)

        # Source IP Risk
        unique_ips = {e.source_ip_address for e in self.events}
        ip_risk_score = 0

        for ip in unique_ips:
            ip_hash = int(hashlib.md5(ip.encode()).hexdigest(), 16) % 100

            if ip.startswith("192.168."):
                ip_risk_score += 0.2
            elif ip_hash > 80:
                ip_risk_score += 0.95
            else:
                ip_risk_score += 0.5

        ip_consistency = 1.0 / len(unique_ips) if unique_ips else 0
        final_ip_score = (ip_risk_score / len(unique_ips)) * 0.7 + (ip_consistency * 0.3)

        # Threat Intel Boost
        threat_boost = sum(
            (e.threat_intel_score or 0) / 100
            for e in self.events
        ) / len(self.events)

        # Pattern Detection
        has_priv_esc = any(e.event_type == "privilege_escalation" for e in self.events)
        has_failed = any(e.event_type == "login_failed" for e in self.events)
        has_password_change = any(e.event_type == "password_change" for e in self.events)
        has_transaction = any(e.event_type == "transaction_initiated" for e in self.events)

        pattern_bonus = 0

        # Classic brute force → escalation
        if has_failed and has_priv_esc:
            pattern_bonus += 0.2

        # Banking fraud chain
        if has_password_change and has_transaction:
            pattern_bonus += 0.25

        base_score = (
            (resource_score * 0.3)
            + (time_score * 0.2)
            + (final_ip_score * 0.2)
            + (threat_boost * 0.2)
            + pattern_bonus
        )

        final_score = 0.95 / (1 + math.exp(-5 * (base_score - 0.5)))

        self.correlation_strength = round(min(max(final_score, 0.05), 0.99), 4)

    def to_dict(self):
        return {
            "incident_id": self.incident_id,
            "user_id": self.user_id,
            "correlation_strength": self.correlation_strength,
            "avg_anomaly_score": self.avg_anomaly_score,
            "events": [e.to_dict() for e in self.events]
        }


def detect_incidents(events):

    user_events = defaultdict(list)

    for event in events:
        user_events[event.user_id].append(event)

    incidents = []
    incident_counter = 1

    print(f"🔍 Total users: {len(user_events)}")

    for user, logs in user_events.items():

        logs.sort(key=lambda x: x.timestamp)

        sequence = []
        incident_created = False 

        for event in logs:

            sequence.append(event)

            has_failed = any(e.event_type == "login_failed" for e in sequence)
            has_priv = any(e.event_type == "privilege_escalation" for e in sequence)
            has_pwd = any(e.event_type == "password_change" for e in sequence)
            has_txn = any(e.event_type == "transaction_initiated" for e in sequence)

            # 🎯 ORIGINAL STRICT CONDITIONS
            if (has_failed and has_priv) or (has_pwd and has_txn):

                incident = Incident(
                    incident_id=incident_counter,
                    user_id=user,
                    events=sequence.copy()
                )

                incident.calculate_metrics()
                incidents.append(incident)

                incident_counter += 1
                incident_created = True  # ✅ mark so fallback does NOT double-fire
                break

        if not incident_created and len(sequence) >= 5:
            scored = [e.anomaly_score for e in sequence if e.anomaly_score is not None]
            if scored:  # ✅ guard against empty anomaly scores
                avg_anomaly = sum(scored) / len(scored)
                print(f"🔎 User {user}: seq_len={len(sequence)}, avg_anomaly={avg_anomaly:.4f}")

                if avg_anomaly > 0.4:
                    print(f"⚠️ Fallback incident created for user {user}")

                    incident = Incident(
                        incident_id=incident_counter,
                        user_id=user,
                        events=sequence[:5]
                    )

                    incident.calculate_metrics()
                    incidents.append(incident)

                    incident_counter += 1

    print(f"🚨 Total incidents detected: {len(incidents)}")

    return incidents