from elasticsearch import Elasticsearch

es = Elasticsearch("http://localhost:9200")


def fetch_vectors():
    res = es.search(
        index="acira_vectors",
        body={"query": {"match_all": {}}},
        size=100_000  # ✅ FIX: was 1000 — truncated 98K+ events, killing detection
    )

    vectors = []
    for hit in res["hits"]["hits"]:
        vectors.append(hit["_source"]["features"])

    return vectors