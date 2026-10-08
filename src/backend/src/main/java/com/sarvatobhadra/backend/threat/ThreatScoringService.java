package com.sarvatobhadra.backend.threat;

import com.sarvatobhadra.backend.alert.Alert;
import com.sarvatobhadra.backend.common.enums.Priority;
import com.sarvatobhadra.backend.common.enums.Severity;
import com.sarvatobhadra.backend.intelligence.IntelligenceReport;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;

/**
 * Threat Scoring and Prioritization Engine service.
 * Computes priority score (0-100) based on PDF specification multi-factor formula:
 * Severity + Source Reliability + Correlation Strength + Target Criticality + Recency + Historical Evidence.
 * Maps score to Priority enum:
 *  - 0-30   -> LOW
 *  - 31-60  -> MEDIUM
 *  - 61-80  -> HIGH
 *  - 81-100 -> CRITICAL
 */
@Service
@Slf4j
public class ThreatScoringService {

    /**
     * Calculates the composite threat score for a cluster based on its associated alerts and reports.
     */
    public int calculateThreatScore(ThreatCluster cluster, List<Alert> alerts, List<IntelligenceReport> reports) {
        log.info("Calculating composite threat score for cluster ID: {}", cluster.getId());

        // 1. Severity Score (Max 25 pts)
        int severityScore = 0;
        if (alerts != null && !alerts.isEmpty()) {
            boolean hasCritical = alerts.stream().anyMatch(a -> a.getSeverity() == Severity.CRITICAL);
            boolean hasHigh = alerts.stream().anyMatch(a -> a.getSeverity() == Severity.HIGH);
            if (hasCritical) severityScore = 25;
            else if (hasHigh) severityScore = 18;
            else severityScore = 10;
        } else {
            severityScore = 15;
        }

        // 2. Source Reliability Score (Max 20 pts)
        int sourceScore = 0;
        long uniqueSources = alerts != null ? alerts.stream().map(Alert::getSource).distinct().count() : 0;
        if (reports != null && !reports.isEmpty()) uniqueSources++;
        if (uniqueSources >= 3) sourceScore = 20; // Multi-source corroboration
        else if (uniqueSources == 2) sourceScore = 14;
        else sourceScore = 8;

        // 3. Correlation Strength (Max 25 pts)
        int correlationStrengthScore = 0;
        double rawCorr = cluster.getCorrelationScore() != null ? cluster.getCorrelationScore() : 50.0;
        correlationStrengthScore = (int) Math.min(25, (rawCorr / 100.0) * 25);

        // 4. Target Criticality (Max 15 pts)
        int targetScore = 10;
        if (cluster.getAffectedTarget() != null) {
            String targetLower = cluster.getAffectedTarget().toLowerCase();
            if (targetLower.contains("defence") || targetLower.contains("defense") || targetLower.contains("core")) {
                targetScore = 15;
            }
        }

        // 5. Recency and Volume (Max 15 pts)
        int recencyScore = 15;
        if (alerts != null && !alerts.isEmpty()) {
            LocalDateTime newestAlert = alerts.stream()
                    .map(Alert::getTimestamp)
                    .max(LocalDateTime::compareTo)
                    .orElse(LocalDateTime.now());
            long hoursAgo = ChronoUnit.HOURS.between(newestAlert, LocalDateTime.now());
            if (hoursAgo > 72) recencyScore = 5;
            else if (hoursAgo > 24) recencyScore = 10;
        }

        int totalScore = severityScore + sourceScore + correlationStrengthScore + targetScore + recencyScore;
        return Math.min(100, Math.max(0, totalScore));
    }

    /**
     * Maps numerical score (0-100) to Priority enum.
     */
    public Priority mapScoreToPriority(int score) {
        if (score <= 30) {
            return Priority.LOW;
        } else if (score <= 60) {
            return Priority.MEDIUM;
        } else if (score <= 80) {
            return Priority.HIGH;
        } else {
            return Priority.CRITICAL;
        }
    }
}
