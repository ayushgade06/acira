from pyod.models.iforest import IForest
import numpy as np


def compute_anomaly_scores(events, feature_df):


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
    from core.ingestion import load_logs
    from core.feature_engineering import extract_features

    logs = load_logs()
    features = extract_features(logs)

    logs_with_scores = compute_anomaly_scores(logs, features)

    print("Top 5 events with anomaly scores:")
    for event in logs_with_scores[:5]:
        print(event.to_dict())
