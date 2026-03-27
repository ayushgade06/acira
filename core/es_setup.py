from elasticsearch import Elasticsearch

# Connect to Elasticsearch
es = Elasticsearch("http://localhost:9200")


def create_index():
    """Create the ACIRA vectors index with correct dimensions"""
    index_name = "acira_vectors"

    mapping = {
        "mappings": {
            "properties": {
                "user_id": {"type": "keyword"},
                "timestamp": {"type": "date"},
                "features": {
                    "type": "dense_vector",
                    "dims": 50  # ✅ FIXED: 50 PCA features (not 49 or 51)
                }
            }
        }
    }

    try:
        # Check if index exists
        if es.indices.exists(index=index_name):
            print("⚠️ Index already exists. Deleting old index...")
            es.indices.delete(index=index_name)
        
        # Create new index
        es.indices.create(index=index_name, body=mapping)
        print("✅ Index created successfully with 50-dimensional vectors")

    except Exception as e:
        print(f"❌ Error creating index: {e}")
        raise


def verify_index():
    """Verify the index was created correctly"""
    index_name = "acira_vectors"
    
    try:
        mapping = es.indices.get_mapping(index=index_name)
        dims = mapping[index_name]['mappings']['properties']['features']['dims']
        print(f"✅ Index verified - Vector dimensions: {dims}")
        return dims
    except Exception as e:
        print(f"❌ Error verifying index: {e}")
        return None


if __name__ == "__main__":
    create_index()
    verify_index()