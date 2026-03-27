from pyod.models.iforest import IForest
from core.vector_loader import fetch_vectors
from core.ingestion import load_logs
import pandas as pd
import numpy as np

def compute_anomaly_scores(events, feature_df):
    """
    Compute anomaly scores using Isolation Forest
    """

    model = IForest(contamination=0.2, random_state=42)
    model.fit(feature_df)

    scores = model.decision_function(feature_df)

    min_score = np.min(scores)
    max_score = np.max(scores)
    normalized_scores = (scores - min_score) / (max_score - min_score + 1e-8)

    for event, score in zip(events, normalized_scores):
        event.anomaly_score = round(float(score), 4)

    return events


if __name__ == "__main__":
    print("🚀 Loading logs (metadata)...")
    logs = load_logs()

    print("🚀 Fetching vectors from Elasticsearch...")
    vectors = fetch_vectors()

    # Convert vectors to DataFrame
    feature_df = pd.DataFrame(vectors)

    print(f"📊 Loaded {len(logs)} logs and {len(vectors)} vectors")

    # ✅ FIX: Handle mismatch gracefully
    if len(logs) != len(vectors):
        print("⚠️ Mismatch detected — aligning logs with vectors...")

        min_len = min(len(logs), len(vectors))

        logs = logs[:min_len]
        feature_df = feature_df.iloc[:min_len]

        print(f"✅ Aligned to {min_len} entries")

    print("🚀 Running anomaly detection...")
    logs_with_scores = compute_anomaly_scores(logs, feature_df)

    print("\n🔥 Top 5 events with anomaly scores:\n")
    for event in logs_with_scores[:5]:
        print(event.to_dict())