package com.sarvatobhadra.backend.threat;


import com.sarvatobhadra.backend.alert.Alert;
import com.sarvatobhadra.backend.intelligence.IntelligenceReport;
import com.sarvatobhadra.backend.threat.ThreatCluster;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Maintains a bounded, representative description for a threat cluster.
 *
 * Instead of appending every alert description, it:
 *  1. Finds the terms that recur across the cluster's alerts and reports (its "theme").
 *  2. Picks the few most representative, non-redundant texts.
 *  3. Builds a compact description capped at MAX_DESCRIPTION_LENGTH,
 *     so the cluster embedding reflects the whole cluster, not just the first alert.
 */
@Service
public class ClusterSummaryService {

    private static final int MAX_DESCRIPTION_LENGTH = 1000;
    private static final int MAX_KEY_TERMS = 12;
    private static final int MAX_ALERT_SNIPPETS = 3;
    private static final int MAX_REPORT_SNIPPETS = 2;
    private static final int MAX_SNIPPET_LENGTH = 220;
    private static final double REDUNDANCY_THRESHOLD = 0.6; // Jaccard similarity

    private static final Set<String> STOP_WORDS = Set.of(
            "a", "an", "the", "and", "or", "of", "to", "in", "on", "at", "for", "with", "by",
            "from", "is", "are", "was", "were", "be", "been", "it", "its", "this", "that",
            "these", "those", "as", "has", "have", "had", "not", "but", "into", "than", "then",
            "alert", "detected", "observed", "reported", "activity", "possible", "potential");

    public String updateDescription(ThreatCluster cluster,
                                    List<Alert> alerts,
                                    List<IntelligenceReport> reports) {

        List<String> alertTexts = alerts.stream()
                .map(Alert::getDescription)
                .filter(this::hasText)
                .collect(Collectors.toList());

        List<String> reportTexts = reports.stream()
                .map(IntelligenceReport::getSummary)
                .filter(this::hasText)
                .collect(Collectors.toList());

        // Nothing new to learn from: keep what the cluster already has
        if (alertTexts.isEmpty() && reportTexts.isEmpty()) {
            return cluster.getDescription();
        }

        List<String> allTexts = new ArrayList<>(alertTexts);
        allTexts.addAll(reportTexts);

        Map<String, Integer> docFrequency = computeDocumentFrequency(allTexts);

        List<String> keyTerms = docFrequency.entrySet().stream()
                .filter(e -> e.getValue() > 1 || allTexts.size() == 1) // recurring terms = cluster theme
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed()
                        .thenComparing(Map.Entry.comparingByKey()))
                .limit(MAX_KEY_TERMS)
                .map(Map.Entry::getKey)
                .collect(Collectors.toList());

        List<String> alertSnippets = pickRepresentative(alertTexts, docFrequency, MAX_ALERT_SNIPPETS);
        List<String> reportSnippets = pickRepresentative(reportTexts, docFrequency, MAX_REPORT_SNIPPETS);

        StringBuilder sb = new StringBuilder();
        sb.append("Threat cluster of ").append(alerts.size()).append(" correlated alert(s)");
        if (!reports.isEmpty()) {
            sb.append(" and ").append(reports.size()).append(" intelligence report(s)");
        }
        sb.append(".");

        if (!keyTerms.isEmpty()) {
            sb.append(" Key themes: ").append(String.join(", ", keyTerms)).append(".");
        }
        if (!alertSnippets.isEmpty()) {
            sb.append(" Representative alert activity: ")
                    .append(String.join(" | ", alertSnippets)).append(".");
        }
        if (!reportSnippets.isEmpty()) {
            sb.append(" Intelligence context: ")
                    .append(String.join(" | ", reportSnippets)).append(".");
        }

        return truncate(sb.toString(), MAX_DESCRIPTION_LENGTH);
    }

    // ---------- helpers ----------

    /** Number of texts each term appears in (a term counts once per text). */
    private Map<String, Integer> computeDocumentFrequency(List<String> texts) {
        Map<String, Integer> df = new HashMap<>();
        for (String text : texts) {
            for (String term : tokenize(text)) {
                df.merge(term, 1, Integer::sum);
            }
        }
        return df;
    }

    /**
     * Greedily selects the texts that best cover the cluster's common terms,
     * skipping any that are near-duplicates of an already selected text.
     */
    private List<String> pickRepresentative(List<String> texts,
                                            Map<String, Integer> docFrequency,
                                            int limit) {
        if (texts.isEmpty()) {
            return Collections.emptyList();
        }

        // Rank candidates by how many cluster-wide terms they contain (length-normalised)
        List<String> ranked = texts.stream()
                .distinct()
                .sorted(Comparator.comparingDouble((String t) -> -representativeness(t, docFrequency)))
                .collect(Collectors.toList());

        List<String> selected = new ArrayList<>();
        List<Set<String>> selectedTokens = new ArrayList<>();

        for (String candidate : ranked) {
            if (selected.size() >= limit) {
                break;
            }
            Set<String> tokens = tokenize(candidate);
            boolean redundant = selectedTokens.stream()
                    .anyMatch(existing -> jaccard(existing, tokens) >= REDUNDANCY_THRESHOLD);
            if (!redundant) {
                selected.add(truncate(candidate.trim(), MAX_SNIPPET_LENGTH));
                selectedTokens.add(tokens);
            }
        }
        return selected;
    }

    private double representativeness(String text, Map<String, Integer> docFrequency) {
        Set<String> tokens = tokenize(text);
        if (tokens.isEmpty()) {
            return 0;
        }
        double sum = 0;
        for (String token : tokens) {
            sum += docFrequency.getOrDefault(token, 0);
        }
        return sum / Math.sqrt(tokens.size());
    }

    private double jaccard(Set<String> a, Set<String> b) {
        if (a.isEmpty() || b.isEmpty()) {
            return 0;
        }
        Set<String> intersection = new HashSet<>(a);
        intersection.retainAll(b);
        Set<String> union = new HashSet<>(a);
        union.addAll(b);
        return (double) intersection.size() / union.size();
    }

    private Set<String> tokenize(String text) {
        Set<String> tokens = new LinkedHashSet<>();
        for (String raw : text.toLowerCase().split("[^a-z0-9._:/-]+")) {
            String token = raw.replaceAll("^[._:/-]+|[._:/-]+$", "");
            if (token.length() > 2 && !STOP_WORDS.contains(token)) {
                tokens.add(token); // keeps IPs, domains, CVE ids, hashes intact
            }
        }
        return tokens;
    }

    private boolean hasText(String s) {
        return s != null && !s.isBlank();
    }

    private String truncate(String text, int max) {
        if (text.length() <= max) {
            return text;
        }
        int cut = text.lastIndexOf(' ', max - 3);
        return text.substring(0, cut > 0 ? cut : max - 3) + "...";
    }
}