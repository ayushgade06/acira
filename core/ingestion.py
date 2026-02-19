import json
from datetime import datetime
from pathlib import Path


class LogEvent:
    def __init__(self, user_id, ip_address, event_type, timestamp, resource_accessed):
        self.user_id = user_id
        self.ip_address = ip_address
        self.event_type = event_type
        self.timestamp = datetime.fromisoformat(timestamp)
        self.resource_accessed = resource_accessed
        self.anomaly_score = None  

    def to_dict(self):
        return {
            "user_id": self.user_id,
            "ip_address": self.ip_address,
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "resource_accessed": self.resource_accessed,
            "anomaly_score": self.anomaly_score
        }


def load_logs(file_path="data/sample_logs.json"):
    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    with open(file_path, "r") as f:
        raw_logs = json.load(f)

    events = []
    for log in raw_logs:
        event = LogEvent(
            user_id=log["user_id"],
            ip_address=log["ip_address"],
            event_type=log["event_type"],
            timestamp=log["timestamp"],
            resource_accessed=log["resource_accessed"]
        )
        events.append(event)

    events.sort(key=lambda x: x.timestamp)

    return events


if __name__ == "__main__":
    logs = load_logs()
    print(f"Total logs loaded: {len(logs)}")
    print("First log:", logs[0].to_dict())
    print("Last log:", logs[-1].to_dict())
