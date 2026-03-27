import pandas as pd
from elasticsearch import Elasticsearch
import numpy as np

es = Elasticsearch("http://localhost:9200")


def upload_vectors(csv_path="data/user_behavior_vectors.csv"):
    df = pd.read_csv(csv_path)

    print("📊 Original shape:", df.shape)

    # ✅ Convert all values to numeric
    df = df.apply(pd.to_numeric, errors='coerce')

    # ✅ Replace NaN and infinite values
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.fillna(0)

    print("✅ Cleaned data")

    for i, row in df.iterrows():
        vector = row.astype(float).tolist()

        doc = {
            "user_id": f"user_{i}",
            "timestamp": "2026-01-01T00:00:00",
            "features": vector
        }

        es.index(index="acira_vectors", id=i, document=doc)

        if i % 1000 == 0:
            print(f"Uploaded {i} vectors")

    print("✅ All vectors uploaded")


if __name__ == "__main__":
    upload_vectors()