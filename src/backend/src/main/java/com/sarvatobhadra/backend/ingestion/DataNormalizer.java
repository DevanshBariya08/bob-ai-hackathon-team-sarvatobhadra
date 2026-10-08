package com.sarvatobhadra.backend.ingestion;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sarvatobhadra.backend.alert.Alert;
import com.sarvatobhadra.backend.client.NlpClient;
import com.sarvatobhadra.backend.common.enums.Severity;
import com.sarvatobhadra.backend.common.enums.SourceType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

/**
 * Normalization layer converting heterogeneous multi-source data formats (SIEM JSON, Cyber Sensor logs,
 * OSINT feeds, PDF text) into the platform's Common Internal Data Model as described in PDF Section 3.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class DataNormalizer {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final NlpClient nlpClient;

    /**
     * Normalizes raw JSON or string input into a standard {@link Alert} entity.
     *
     * @param rawData Raw string payload or JSON string
     * @param defaultSource Ingestion source category (SIEM, SENSOR, OSINT)
     * @return Normalized {@link Alert} entity
     */
    public Alert normalizeAlert(String rawData, SourceType defaultSource) {
        log.info("Normalizing raw data from source: {}", defaultSource);

        SourceType source = defaultSource != null ? defaultSource : SourceType.SIEM;
        Severity severity = Severity.MEDIUM;
        String eventType = "NETWORK_ACTIVITY";
        String description = rawData;
        String target = null;
        String threatActor = null;
        LocalDateTime timestamp = LocalDateTime.now();

        try {
            if (rawData.trim().startsWith("{")) {
                JsonNode json = objectMapper.readTree(rawData);

                if (json.has("source")) {
                    try { source = SourceType.valueOf(json.get("source").asText().toUpperCase()); } catch (Exception ignored) {}
                }
                if (json.has("severity")) {
                    try { severity = Severity.valueOf(json.get("severity").asText().toUpperCase()); } catch (Exception ignored) {}
                }
                if (json.has("eventType")) {
                    eventType = json.get("eventType").asText();
                }
                if (json.has("description")) {
                    description = json.get("description").asText();
                }
                if (json.has("target")) {
                    target = json.get("target").asText();
                }
                if (json.has("threatActor")) {
                    threatActor = json.get("threatActor").asText();
                }
            }
        } catch (Exception e) {
            log.warn("Payload is non-JSON or custom formatted text. Utilizing AI NLP extraction for normalization.");
        }

        // Run AI NLP Extraction to supplement missing fields
        NlpClient.ExtractedEntities extracted = nlpClient.extractEntities(description);
        if (target == null) target = extracted.getTargetSystem();
        if (threatActor == null) threatActor = extracted.getThreatActor();

        return Alert.builder()
                .source(source)
                .timestamp(timestamp)
                .severity(severity)
                .eventType(eventType)
                .description(description)
                .rawPayload(rawData)
                .target(target)
                .threatActor(threatActor)
                .createdAt(LocalDateTime.now())
                .build();
    }
}
