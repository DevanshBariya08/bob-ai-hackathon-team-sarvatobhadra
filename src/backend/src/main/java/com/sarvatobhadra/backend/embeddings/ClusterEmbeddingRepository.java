package com.sarvatobhadra.backend.embeddings;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public class ClusterEmbeddingRepository {

    private final JdbcTemplate jdbcTemplate;

    public ClusterEmbeddingRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public Optional<float[]> findByClusterId(Long clusterId) {

        return jdbcTemplate.query(
                """
                SELECT embedding::text
                FROM cluster_embeddings
                WHERE cluster_id = ?
                """,
                rs -> {

                    if (!rs.next()) {
                        return Optional.empty();
                    }

                    return Optional.of(
                            EmbeddingVector.fromSqlVector(
                                    rs.getString("embedding")
                            )
                    );
                },
                clusterId
        );
    }

    public void saveIfAbsent(
            Long clusterId,
            float[] embedding,
            String description,
            int alertCount
    ) {

        String vector = EmbeddingVector.toSqlVector(embedding);

        jdbcTemplate.update(
                """
                INSERT INTO cluster_embeddings (
                    cluster_id,
                    embedding,
                    description,
                    alert_count,
                    description_version,
                    created_at,
                    updated_at
                )
                VALUES (
                    ?,
                    CAST(? AS vector),
                    jsonb_build_object('text', ?),
                    ?,
                    1,
                    now(),
                    now()
                )
                ON CONFLICT (cluster_id) DO NOTHING
                """,
                clusterId,
                vector,
                description,
                alertCount
        );
    }

    public void updateEmbedding(
            Long clusterId,
            float[] embedding,
            String description,
            int alertCount
    ) {

        String vector = EmbeddingVector.toSqlVector(embedding);

        jdbcTemplate.update(
                """
                INSERT INTO cluster_embeddings (
                    cluster_id,
                    embedding,
                    description,
                    alert_count,
                    description_version,
                    created_at,
                    updated_at
                )
                VALUES (
                    ?,
                    CAST(? AS vector),
                    jsonb_build_object('text', ?),
                    ?,
                    1,
                    now(),
                    now()
                )
                ON CONFLICT (cluster_id)
                DO UPDATE SET
                    embedding = EXCLUDED.embedding,
                    description = EXCLUDED.description,
                    alert_count = EXCLUDED.alert_count,
                    description_version =
                        cluster_embeddings.description_version + 1,
                    updated_at = now()
                """,
                clusterId,
                vector,
                description,
                alertCount
        );
    }
}