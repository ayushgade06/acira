from collections import defaultdict


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

        import math
        import hashlib

        if len(self.events) > 1:
            timestamps = [e.timestamp.timestamp() for e in self.events]
            intervals = [t2 - t1 for t1, t2 in zip(timestamps, timestamps[1:])]
            avg_interval = sum(intervals) / len(intervals) if intervals else 0
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals) if intervals else 0
            
            total_duration = timestamps[-1] - timestamps[0]
            time_score = math.exp(-total_duration / 3600)  
        else:
            time_score = 0.5

        critical_weights = {
            "customer_financial_db": 0.9,
            "core_banking_admin_panel": 1.0,
            "swift_gateway": 1.0,
            "employee_db": 0.7,
            "payroll_db": 0.8,
            "analytics_db": 0.6,
            "NA": 0.1
        }
        resource_score = sum(critical_weights.get(e.resource_accessed, 0.3) for e in self.events) / len(self.events)

        unique_ips = {e.ip_address for e in self.events}
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

        has_priv_esc = any(e.event_type == "privilege_escalation" for e in self.events)
        has_failed_logins = any(e.event_type == "login_failed" for e in self.events)
        
        pattern_bonus = 0.2 if (has_priv_esc and has_failed_logins) else 0.0


        base_score = (resource_score * 0.4) + (time_score * 0.3) + (final_ip_score * 0.2) + pattern_bonus

        damping = (self.incident_id % 10) * 0.001

        final_score = 0.95 / (1 + math.exp(-5 * (base_score - 0.5))) + damping

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

    for user, logs in user_events.items():
        logs.sort(key=lambda x: x.timestamp)

        failed_count = 0
        sequence = []

        for event in logs:
            if event.event_type == "login_failed":
                failed_count += 1
                sequence.append(event)

            elif event.event_type == "login_success" and failed_count >= 3:
                sequence.append(event)

            elif event.event_type == "db_access" and sequence:
                sequence.append(event)

            elif event.event_type == "privilege_escalation" and sequence:
                sequence.append(event)

                # Pattern complete → create incident
                incident = Incident(
                    incident_id=incident_counter,
                    user_id=user,
                    events=sequence.copy()
                )
                incident.calculate_metrics()
                incidents.append(incident)

                incident_counter += 1
                break

    return incidents

if __name__ == "__main__":
    from core.ingestion import load_logs
    from core.feature_engineering import extract_features
    from core.anomaly import compute_anomaly_scores

    logs = load_logs()
    features = extract_features(logs)
    logs = compute_anomaly_scores(logs, features)

    incidents = detect_incidents(logs)

    print(f"Total incidents detected: {len(incidents)}")

    if incidents:
        print(incidents[0].to_dict())
