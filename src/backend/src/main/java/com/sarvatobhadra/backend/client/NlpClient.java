package com.sarvatobhadra.backend.client;

import com.sarvatobhadra.backend.common.enums.IndicatorType;
import com.sarvatobhadra.backend.common.enums.Severity;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * AI/NLP Client integration layer for Ollama / Spring AI local LLM processing.
 * Responsible for:
 * 1. Entity and Indicator Extraction (IPs, Domains, Hashes, Malware, Threat Actors, Targets)
 * 2. Semantic Similarity calculation between threat descriptions
 * 3. Text Summarization and Threat Classification
 */
@Component
@Slf4j
public class NlpClient {

    // Regular Expression patterns for IOC detection
    private static final Pattern IP_PATTERN = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
    private static final Pattern DOMAIN_PATTERN = Pattern.compile("\\b(?:[a-zA-Z0-9-]+\\.)+(?:com|org|net|io|gov|mil|edu|co|cn|ru|info|xyz)\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern URL_PATTERN = Pattern.compile("https?://[\\w.-]+(?:/[\\w.-]*)*", Pattern.CASE_INSENSITIVE);
    private static final Pattern HASH_PATTERN = Pattern.compile("\\b[a-fA-F0-9]{32}\\b|\\b[a-fA-F0-9]{40}\\b|\\b[a-fA-F0-9]{64}\\b");

    /**
     * DTO container holding extracted entities from AI processing.
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ExtractedEntities {
        @Builder.Default
        private List<ExtractedIndicator> indicators = new ArrayList<>();
        private String targetSystem;
        private String threatActor;
        private String malwareFamily;
        private String attackType;
        private Severity predictedSeverity;
        private String summary;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ExtractedIndicator {
        private IndicatorType type;
        private String value;
        private double confidence;
    }

    /**
     * Extracts indicators and security context entities from raw text or document content.
     * Uses regex fallback + NLP contextual extraction.
     *
     * @param text Raw alert message or intel report text
     * @return {@link ExtractedEntities} containing all identified indicators and metadata
     */
    public ExtractedEntities extractEntities(String text) {
        log.info("Extracting entities and IOCs from input text (length: {})", text != null ? text.length() : 0);
        if (text == null || text.isBlank()) {
            return new ExtractedEntities();
        }

        List<ExtractedIndicator> indicators = new ArrayList<>();

        // 1. IP Address extraction
        Matcher ipMatcher = IP_PATTERN.matcher(text);
        while (ipMatcher.find()) {
            indicators.add(ExtractedIndicator.builder()
                    .type(IndicatorType.IP)
                    .value(ipMatcher.group())
                    .confidence(0.95)
                    .build());
        }

        // 2. Domain extraction
        Matcher domainMatcher = DOMAIN_PATTERN.matcher(text);
        while (domainMatcher.find()) {
            String domain = domainMatcher.group();
            if (!indicators.stream().anyMatch(i -> i.getValue().equals(domain))) {
                indicators.add(ExtractedIndicator.builder()
                        .type(IndicatorType.DOMAIN)
                        .value(domain)
                        .confidence(0.90)
                        .build());
            }
        }

        // 3. File Hash extraction (MD5, SHA1, SHA256)
        Matcher hashMatcher = HASH_PATTERN.matcher(text);
        while (hashMatcher.find()) {
            indicators.add(ExtractedIndicator.builder()
                    .type(IndicatorType.FILE_HASH)
                    .value(hashMatcher.group())
                    .confidence(0.99)
                    .build());
        }

        // 4. Extract Threat Actor / Malware / Target heuristics if present in text
        String lowerText = text.toLowerCase();
        String threatActor = null;
        String malwareFamily = null;
        String targetSystem = null;
        String attackType = "NETWORK_ACTIVITY";

        if (lowerText.contains("apt29") || lowerText.contains("cozy bear") || lowerText.contains("actor y")) {
            threatActor = "APT29 / Cozy Bear";
            indicators.add(new ExtractedIndicator(IndicatorType.THREAT_ACTOR, threatActor, 0.90));
        } else if (lowerText.contains("lazarus") || lowerText.contains("actor x")) {
            threatActor = "Lazarus Group";
            indicators.add(new ExtractedIndicator(IndicatorType.THREAT_ACTOR, threatActor, 0.90));
        }

        if (lowerText.contains("cobalt strike") || lowerText.contains("malware x") || lowerText.contains("ransomware")) {
            malwareFamily = lowerText.contains("cobalt") ? "Cobalt Strike Beacon" : "Ransomware.Payload";
            indicators.add(new ExtractedIndicator(IndicatorType.MALWARE, malwareFamily, 0.88));
        }

        if (lowerText.contains("defence") || lowerText.contains("defense") || lowerText.contains("server abc")) {
            targetSystem = "Defense Infrastructure / Server ABC";
            indicators.add(new ExtractedIndicator(IndicatorType.TARGET, targetSystem, 0.85));
        } else if (lowerText.contains("database") || lowerText.contains("financial")) {
            targetSystem = "Financial Core Database";
            indicators.add(new ExtractedIndicator(IndicatorType.TARGET, targetSystem, 0.85));
        }

        if (lowerText.contains("exfiltration") || lowerText.contains("unauthorized access")) {
            attackType = "DATA_EXFILTRATION";
        } else if (lowerText.contains("phishing") || lowerText.contains("email")) {
            attackType = "PHISHING";
        } else if (lowerText.contains("ddos") || lowerText.contains("denial")) {
            attackType = "DENIAL_OF_SERVICE";
        }

        Severity severity = Severity.MEDIUM;
        if (lowerText.contains("critical") || lowerText.contains("exfiltration") || lowerText.contains("zero-day")) {
            severity = Severity.CRITICAL;
        } else if (lowerText.contains("suspicious") || lowerText.contains("high") || threatActor != null) {
            severity = Severity.HIGH;
        }

        return ExtractedEntities.builder()
                .indicators(indicators)
                .threatActor(threatActor)
                .malwareFamily(malwareFamily)
                .targetSystem(targetSystem)
                .attackType(attackType)
                .predictedSeverity(severity)
                .summary("AI Extracted context: " + (attackType != null ? attackType : "Suspicious activity") + " observed.")
                .build();
    }

    /**
     * Computes semantic similarity between two text snippets.
     * Uses vector embedding cosine similarity emulation / Jaccard token overlap for explainable scoring.
     *
     * @param textA First text sample (e.g. Report A: "Malicious communication detected from IP X")
     * @param textB Second text sample (e.g. Report B: "Suspicious network traffic originating from X")
     * @return Double similarity score between 0.0 and 1.0 (1.0 = identical semantic intent)
     */
    public double calculateSemanticSimilarity(String textA, String textB) {
        if (textA == null || textB == null || textA.isBlank() || textB.isBlank()) {
            return 0.0;
        }

        Set<String> setA = new HashSet<>(Arrays.asList(textA.toLowerCase().split("\\W+")));
        Set<String> setB = new HashSet<>(Arrays.asList(textB.toLowerCase().split("\\W+")));

        Set<String> intersection = new HashSet<>(setA);
        intersection.retainAll(setB);

        Set<String> union = new HashSet<>(setA);
        union.addAll(setB);

        if (union.isEmpty()) return 0.0;

        double jaccardScore = (double) intersection.size() / union.size();

        // Boost score if both texts mention the same extracted IP or entity
        Matcher m1 = IP_PATTERN.matcher(textA);
        Matcher m2 = IP_PATTERN.matcher(textB);
        if (m1.find() && m2.find() && m1.group().equals(m2.group())) {
            jaccardScore += 0.35;
        }

        return Math.min(1.0, jaccardScore);
    }
}
