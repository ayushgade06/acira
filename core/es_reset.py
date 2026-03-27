from elasticsearch import Elasticsearch

es = Elasticsearch("http://localhost:9200")


def reset_index():
    """Delete and recreate the ACIRA vectors index"""
    index_name = "acira_vectors"
    
    try:
        # Delete if exists
        if es.indices.exists(index=index_name):
            print(f"🗑️ Deleting existing index: {index_name}")
            es.indices.delete(index=index_name)
            print("✅ Index deleted")
        
        # Recreate
        mapping = {
            "mappings": {
                "properties": {
                    "user_id": {"type": "keyword"},
                    "timestamp": {"type": "date"},
                    "features": {
                        "type": "dense_vector",
                        "dims": 50
                    }
                }
            }
        }
        
        es.indices.create(index=index_name, body=mapping)
        print(f"✅ Index recreated: {index_name}")
        print("✅ Ready for vector upload")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        raise


if __name__ == "__main__":
    reset_index()