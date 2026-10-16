package com.sarvatobhadra.backend.embeddings;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.List;

@Component
public class OllamaEmbeddingClient {

    private final RestClient restClient;
    private final String model;

    public OllamaEmbeddingClient(
            @Value("${ollama.base-url:http://localhost:11434}") String baseUrl,
            @Value("${ollama.embedding-model:nomic-embed-text}") String model
    ) {
        this.restClient = RestClient.builder()
                .baseUrl(baseUrl)
                .build();

        this.model = model;
    }

    public float[] generateEmbedding(String text) {

        if (text == null || text.isBlank()) {
            throw new IllegalArgumentException(
                    "Text cannot be empty when generating an embedding"
            );
        }

        EmbedResponse response = restClient.post()
                .uri("/api/embed")
                .contentType(MediaType.APPLICATION_JSON)
                .body(new EmbedRequest(model, text))
                .retrieve()
                .body(EmbedResponse.class);

        if (response == null
                || response.embeddings() == null
                || response.embeddings().isEmpty()) {

            throw new IllegalStateException(
                    "Ollama returned an empty embedding response"
            );
        }

        List<Double> values = response.embeddings().get(0);

        if (values == null || values.isEmpty()) {
            throw new IllegalStateException(
                    "Ollama returned an empty embedding vector"
            );
        }

        float[] vector = new float[values.size()];

        for (int i = 0; i < values.size(); i++) {
            vector[i] = values.get(i).floatValue();
        }

        if (vector.length != 768) {
            throw new IllegalStateException(
                    "Expected a 768-dimensional embedding, but received "
                            + vector.length
            );
        }

        return vector;
    }

    private record EmbedRequest(
            String model,
            String input
    ) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record EmbedResponse(
            List<List<Double>> embeddings
    ) {}
}
