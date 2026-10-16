package com.sarvatobhadra.backend.embeddings;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class EmbeddingService {

    private final OllamaEmbeddingClient ollamaEmbeddingClient;
    private final AlertEmbeddingRepository alertEmbeddingRepository;
    private final ClusterEmbeddingRepository clusterEmbeddingRepository;

    public EmbeddingService(
            OllamaEmbeddingClient ollamaEmbeddingClient,
            AlertEmbeddingRepository alertEmbeddingRepository,
            ClusterEmbeddingRepository clusterEmbeddingRepository
    ) {
        this.ollamaEmbeddingClient = ollamaEmbeddingClient;
        this.alertEmbeddingRepository = alertEmbeddingRepository;
        this.clusterEmbeddingRepository = clusterEmbeddingRepository;
    }

    @Transactional
    public float[] getOrCreateAlertEmbedding(
            Long alertId,
            String description
    ) {

        return alertEmbeddingRepository.findByAlertId(alertId)
                .orElseGet(() -> {

                    float[] embedding =
                            ollamaEmbeddingClient.generateEmbedding(description);

                    alertEmbeddingRepository.save(
                            alertId,
                            embedding,
                            description
                    );

                    return embedding;
                });
    }

    @Transactional
    public float[] getOrCreateClusterEmbedding(
            Long clusterId,
            String description,
            int alertCount
    ) {

        return clusterEmbeddingRepository.findByClusterId(clusterId)
                .orElseGet(() -> {

                    float[] embedding =
                            ollamaEmbeddingClient.generateEmbedding(description);

                    clusterEmbeddingRepository.saveIfAbsent(
                            clusterId,
                            embedding,
                            description,
                            alertCount
                    );

                    // Fetch again in case another transaction created it first.
                    return clusterEmbeddingRepository.findByClusterId(clusterId)
                            .orElseThrow(() ->
                                    new IllegalStateException(
                                            "Cluster embedding could not be saved"
                                    )
                            );
                });
    }

    @Transactional
    public void refreshClusterEmbedding(
            Long clusterId,
            String updatedDescription,
            int alertCount
    ) {

        float[] embedding =
                ollamaEmbeddingClient.generateEmbedding(updatedDescription);

        clusterEmbeddingRepository.updateEmbedding(
                clusterId,
                embedding,
                updatedDescription,
                alertCount
        );
    }

    public double cosineSimilarity(float[] vectorA, float[] vectorB) {

        if (vectorA == null || vectorB == null
                || vectorA.length == 0
                || vectorA.length != vectorB.length) {

            return 0.0;
        }

        double dotProduct = 0.0;
        double magnitudeA = 0.0;
        double magnitudeB = 0.0;

        for (int i = 0; i < vectorA.length; i++) {

            dotProduct += (double) vectorA[i] * vectorB[i];

            magnitudeA += (double) vectorA[i] * vectorA[i];
            magnitudeB += (double) vectorB[i] * vectorB[i];
        }

        if (magnitudeA == 0.0 || magnitudeB == 0.0) {
            return 0.0;
        }

        double similarity = dotProduct /
                (Math.sqrt(magnitudeA) * Math.sqrt(magnitudeB));

        // Protect against floating-point rounding errors.
        return Math.max(-1.0, Math.min(1.0, similarity));
    }
}