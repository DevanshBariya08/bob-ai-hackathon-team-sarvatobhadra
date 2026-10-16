package com.sarvatobhadra.backend.embeddings;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public class AlertEmbeddingRepository {

    private final JdbcTemplate jdbcTemplate;

    public AlertEmbeddingRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public Optional<float[]> findByAlertId(Long alertId) {

        return jdbcTemplate.query(
                """
                SELECT embedding::text
                FROM alert_embeddings
                WHERE alert_id = ?
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
                alertId
        );
    }

    public void save(Long alertId, float[] embedding, String description) {

        String vector = EmbeddingVector.toSqlVector(embedding);

        jdbcTemplate.update(
                """
                INSERT INTO alert_embeddings (
                    alert_id,
                    embedding,
                    description,
                    created_at,
                    updated_at
                )
                VALUES (
                    ?,
                    CAST(? AS vector),
                    jsonb_build_object('text', ?),
                    now(),
                    now()
                )
                ON CONFLICT (alert_id)
                DO UPDATE SET
                    embedding = EXCLUDED.embedding,
                    description = EXCLUDED.description,
                    updated_at = now()
                """,
                alertId,
                vector,
                description
        );
    }
}