import json
from datetime import datetime
from pathlib import Path


def mask_value(value):
    if value is None:
        return None
    return "*" * len(str(value))


class LogEvent:
    def __init__(
        self,
        user_id,
        source_ip_address,
        destination_ip_address,
        event_type,
        timestamp,
        resource_accessed,
        dns_query=None,
        file_path=None,
        file_hash=None,
        username=None,
        hostname=None,
        geo=None,
        threat_intel_score=None
    ):
        self.user_id = user_id
        self.source_ip_address = source_ip_address
        self.destination_ip_address = destination_ip_address
        self.event_type = event_type
        self.timestamp = datetime.fromisoformat(timestamp)
        self.resource_accessed = resource_accessed

        # EDR Fields
        self.dns_query = dns_query
        self.file_path = file_path
        self.file_hash = file_hash
        self.username = username
        self.hostname = hostname
        self.geo = geo or {}

        # SIEM Field
        self.threat_intel_score = threat_intel_score

        # ML Field
        self.anomaly_score = None

    # ✅ Only these 4 fields are masked
    def to_dict(self):
        return {
            "user_id": self.user_id,
            "source_ip_address": self.source_ip_address,
            "destination_ip_address": self.destination_ip_address,
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "resource_accessed": self.resource_accessed,
            "dns_query": self.dns_query,  # NOT masked
            "file_path": mask_value(self.file_path),  # masked
            "file_hash": mask_value(self.file_hash),  # masked
            "username": mask_value(self.username),    # masked
            "hostname": mask_value(self.hostname),    # masked
            "geo": self.geo,  # NOT masked
            "threat_intel_score": self.threat_intel_score,
            "anomaly_score": self.anomaly_score
        }


def load_logs(file_path="data/sample_logs.json"):
    file_path = Path(file_path)

    with open(file_path, "r") as f:
        raw_logs = json.load(f)

    events = []
    for log in raw_logs:
        event = LogEvent(
            user_id=log["user_id"],
            source_ip_address=log["source_ip_address"],
            destination_ip_address=log["destination_ip_address"],
            event_type=log["event_type"],
            timestamp=log["timestamp"],
            resource_accessed=log["resource_accessed"],
            dns_query=log.get("dns_query"),
            file_path=log.get("file_path"),
            file_hash=log.get("file_hash"),
            username=log.get("username"),
            hostname=log.get("hostname"),
            geo=log.get("geo"),
            threat_intel_score=log.get("threat_intel_score")
        )
        events.append(event)

    events.sort(key=lambda x: x.timestamp)
    return events
