import pandas as pd
from elasticsearch import Elasticsearch
import numpy as np
from pathlib import Path

es = Elasticsearch("http://localhost:9200")


def upload_vectors(csv_path="data/user_behavior_vectors.csv"):
    """
    Upload user behavior vectors to Elasticsearch
    Handles the CSV properly and cleans data
    """
    csv_path = Path(csv_path)
    
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV file not found: {csv_path}")
    
    print(f"📊 Loading vectors from: {csv_path}")
    df = pd.read_csv(csv_path)
    
    print(f"📊 Original shape: {df.shape}")
    print(f"📊 Columns: {df.columns.tolist()[:5]}...")
    
    # ✅ Separate user_id from features
    if 'user_id' in df.columns:
        user_ids = df['user_id'].tolist()
        feature_df = df.drop(columns=['user_id'])
    else:
        user_ids = [f"user_{i}" for i in range(len(df))]
        feature_df = df
    
    print(f"📊 Feature columns: {len(feature_df.columns)}")
    
    # ✅ Convert all values to numeric
    feature_df = feature_df.apply(pd.to_numeric, errors='coerce')
    
    # ✅ Replace NaN and infinite values
    feature_df = feature_df.replace([np.inf, -np.inf], np.nan)
    feature_df = feature_df.fillna(0)
    
    # ✅ Verify dimensions
    expected_dims = 50
    if feature_df.shape[1] != expected_dims:
        print(f"⚠️ Warning: Expected {expected_dims} features, got {feature_df.shape[1]}")
        if feature_df.shape[1] > expected_dims:
            print(f"✂️ Trimming to {expected_dims} features")
            feature_df = feature_df.iloc[:, :expected_dims]
        else:
            raise ValueError(f"Not enough features: {feature_df.shape[1]} < {expected_dims}")
    
    print("✅ Data cleaned and validated")
    
    # ✅ Upload to Elasticsearch
    success_count = 0
    error_count = 0
    
    for i, (user_id, row) in enumerate(zip(user_ids, feature_df.values)):
        try:
            vector = row.astype(float).tolist()
            
            # Verify vector length
            if len(vector) != expected_dims:
                print(f"⚠️ Skipping row {i}: Invalid vector length {len(vector)}")
                error_count += 1
                continue
            
            doc = {
                "user_id": str(user_id),
                "timestamp": "2026-01-01T00:00:00",
                "features": vector
            }
            
            es.index(index="acira_vectors", id=i, document=doc)
            success_count += 1
            
            if (i + 1) % 100 == 0:
                print(f"⏳ Uploaded {i + 1}/{len(feature_df)} vectors...")
                
        except Exception as e:
            print(f"❌ Error uploading row {i}: {e}")
            error_count += 1
            continue
    
    print(f"\n✅ Upload complete!")
    print(f"   Success: {success_count}")
    print(f"   Errors: {error_count}")
    print(f"   Total: {success_count + error_count}")
    
    return success_count, error_count


def verify_upload():
    """Verify vectors were uploaded correctly"""
    try:
        result = es.count(index="acira_vectors")
        count = result['count']
        print(f"\n✅ Verification: {count} vectors in Elasticsearch")
        
        # Sample a document
        sample = es.search(
            index="acira_vectors",
            body={"query": {"match_all": {}}, "size": 1}
        )
        
        if sample['hits']['hits']:
            doc = sample['hits']['hits'][0]['_source']
            print(f"✅ Sample vector length: {len(doc['features'])}")
            print(f"✅ Sample user_id: {doc['user_id']}")
        
        return count
    except Exception as e:
        print(f"❌ Verification failed: {e}")
        return 0


if __name__ == "__main__":
    try:
        success, errors = upload_vectors()
        verify_upload()
    except Exception as e:
        print(f"❌ Upload failed: {e}")
        import traceback
        traceback.print_exc()