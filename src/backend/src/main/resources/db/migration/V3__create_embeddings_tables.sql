-- 1. Enable pgvector in this database (installed on the server, but not yet created here)
CREATE EXTENSION IF NOT EXISTS vector;

-- 2. Alert embeddings (one row per alert)
CREATE TABLE alert_embeddings (
    id               BIGSERIAL PRIMARY KEY,
    alert_id         BIGINT       NOT NULL UNIQUE
                     REFERENCES alerts(id) ON DELETE CASCADE,
    embedding        vector(768)  NOT NULL,
    description      JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- 3. Cluster embeddings (one row per cluster, updated as the description changes)
CREATE TABLE cluster_embeddings (
    id                  BIGSERIAL PRIMARY KEY,
    cluster_id          BIGINT       NOT NULL UNIQUE
                        REFERENCES threat_clusters(id) ON DELETE CASCADE,
    embedding           vector(768)  NOT NULL,
    description_version INT          NOT NULL DEFAULT 1,  -- bump when the cluster description changes
    alert_count         INT          NOT NULL DEFAULT 0,
    description         JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- 4. Cosine-distance ANN indexes (HNSW)
CREATE INDEX idx_alert_embeddings_hnsw
    ON alert_embeddings USING hnsw (embedding vector_cosine_ops);

CREATE INDEX idx_cluster_embeddings_hnsw
    ON cluster_embeddings USING hnsw (embedding vector_cosine_ops);