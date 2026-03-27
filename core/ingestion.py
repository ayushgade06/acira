import json
from datetime import datetime
from pathlib import Path
from elasticsearch import Elasticsearch

# Connect to Elasticsearch
es = Elasticsearch("http://localhost:9200")


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

        self.dns_query = dns_query
        self.file_path = file_path
        self.file_hash = file_hash
        self.username = username
        self.hostname = hostname
        self.geo = geo or {}

        self.threat_intel_score = threat_intel_score
        self.anomaly_score = None

    def to_dict(self):
        return {
            "user_id": self.user_id,
            "source_ip_address": self.source_ip_address,
            "destination_ip_address": self.destination_ip_address,
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "resource_accessed": self.resource_accessed,
            "dns_query": self.dns_query,
            "file_path": mask_value(self.file_path),
            "file_hash": mask_value(self.file_hash),
            "username": mask_value(self.username),
            "hostname": mask_value(self.hostname),
            "geo": self.geo,
            "threat_intel_score": self.threat_intel_score,
            "anomaly_score": self.anomaly_score
        }


# ✅ NEW: Push logs to Elasticsearch
def ingest_logs_to_es(file_path="data/sample_logs.json"):
    file_path = Path(file_path)

    with open(file_path, "r") as f:
        raw_logs = json.load(f)

    for i, log in enumerate(raw_logs):
        es.index(index="acira_logs", id=i, document=log)

    print("✅ Logs ingested into Elasticsearch")


# ✅ NEW: Fetch logs from Elasticsearch
def load_logs_from_es():
    res = es.search(
        index="acira_logs",
        body={"query": {"match_all": {}}},
        size=1000
    )

    raw_logs = [hit["_source"] for hit in res["hits"]["hits"]]

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


# ❌ OLD JSON loader (keep optional)
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