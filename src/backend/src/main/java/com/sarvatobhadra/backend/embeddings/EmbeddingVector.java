package com.sarvatobhadra.backend.embeddings;

import java.util.StringJoiner;

// this utility class convert between Java arrays and PostgreSQL's pgvector representation.
public final class EmbeddingVector {

    private EmbeddingVector() {
    }

    public static String toSqlVector(float[] vector) {

        if (vector == null || vector.length != 768) {
            throw new IllegalArgumentException(
                    "Embedding must contain exactly 768 dimensions"
            );
        }

        StringJoiner joiner = new StringJoiner(",", "[", "]");

        for (float value : vector) {

            if (!Float.isFinite(value)) {
                throw new IllegalArgumentException(
                        "Embedding contains a non-finite value"
                );
            }

            joiner.add(Float.toString(value));
        }

        return joiner.toString();
    }

    public static float[] fromSqlVector(String value) {

        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(
                    "Database embedding cannot be empty"
            );
        }

        String cleaned = value.trim();

        if (cleaned.startsWith("[") && cleaned.endsWith("]")) {
            cleaned = cleaned.substring(1, cleaned.length() - 1);
        }

        String[] parts = cleaned.split(",");

        if (parts.length != 768) {
            throw new IllegalStateException(
                    "Expected 768 dimensions but received " + parts.length
            );
        }

        float[] vector = new float[parts.length];

        for (int i = 0; i < parts.length; i++) {
            vector[i] = Float.parseFloat(parts[i].trim());
        }

        return vector;
    }
}