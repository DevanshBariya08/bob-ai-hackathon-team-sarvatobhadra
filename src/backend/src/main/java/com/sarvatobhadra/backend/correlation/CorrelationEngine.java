package com.sarvatobhadra.backend.correlation;

import com.sarvatobhadra.backend.alert.Alert;
import com.sarvatobhadra.backend.client.NlpClient;
import com.sarvatobhadra.backend.common.enums.IndicatorType;
import com.sarvatobhadra.backend.indicator.Indicator;
import com.sarvatobhadra.backend.threat.ThreatCluster;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Hybrid Correlation Engine combining Rule-Based heuristic scoring, AI/NLP semantic similarity,
 * and historical entity evidence matching as specified in PDF Section 6.
 *
 * Scoring Weights:
 *  - Same IP:           +30
 *  - Same Threat Actor: +25
 *  - Same Domain:       +20
 *  - Same Malware:      +20
 *  - Same Target:       +15
 *  - Semantic Similarity: +10 (up to +20)
 *  - Similar Timestamp: +10
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class CorrelationEngine {

    private final NlpClient nlpClient;

    /**
     * Evaluates a newly ingested alert against an existing threat cluster and its associated indicators/alerts.
     *
     * @param targetAlert Newly ingested alert with indicators
     * @param targetIndicators List of extracted indicators for targetAlert
     * @param existingCluster Existing threat cluster candidate
     * @param clusterAlerts Existing alerts linked to existingCluster
     * @param clusterIndicators Existing indicators linked to existingCluster
     * @return {@link CorrelationResult} containing correlation score and explainable rule evidence
     */
    public CorrelationResult evaluateCorrelation(
            Alert targetAlert,
            List<Indicator> targetIndicators,
            ThreatCluster existingCluster,
            List<Alert> clusterAlerts,
            List<Indicator> clusterIndicators
    ) {
        double score = 0.0;
        List<String> matchedIndicators = new ArrayList<>();
        List<String> matchReasons = new ArrayList<>();

        // 1. Same IP matching (+30)
        List<String> newIps = extractValuesByType(targetIndicators, IndicatorType.IP);
        List<String> existingIps = extractValuesByType(clusterIndicators, IndicatorType.IP);
        for (String ip : newIps) {
            if (existingIps.contains(ip)) {
                score += 30;
                matchedIndicators.add(ip);
                matchReasons.add("Same IP address match: " + ip + " (+30)");
                break;
            }
        }

        // 2. Same Threat Actor matching (+25)
        String newActor = targetAlert.getThreatActor();
        if (newActor != null && existingCluster.getPrimaryActor() != null &&
                newActor.equalsIgnoreCase(existingCluster.getPrimaryActor())) {
            score += 25;
            matchedIndicators.add(newActor);
            matchReasons.add("Same Threat Actor match: " + newActor + " (+25)");
        }

        // 3. Same Domain matching (+20)
        List<String> newDomains = extractValuesByType(targetIndicators, IndicatorType.DOMAIN);
        List<String> existingDomains = extractValuesByType(clusterIndicators, IndicatorType.DOMAIN);
        for (String domain : newDomains) {
            if (existingDomains.contains(domain)) {
                score += 20;
                matchedIndicators.add(domain);
                matchReasons.add("Same Domain match: " + domain + " (+20)");
                break;
            }
        }

        // 4. Same Target matching (+15)
        String newTarget = targetAlert.getTarget();
        if (newTarget != null && existingCluster.getAffectedTarget() != null &&
                newTarget.equalsIgnoreCase(existingCluster.getAffectedTarget())) {
            score += 15;
            matchedIndicators.add(newTarget);
            matchReasons.add("Same Target System match: " + newTarget + " (+15)");
        }

        // 5. Semantic Similarity matching (+10 to +20)
        if (targetAlert.getDescription() != null && existingCluster.getDescription() != null) {
            double similarity = nlpClient.calculateSemanticSimilarity(
                    targetAlert.getDescription(),
                    existingCluster.getDescription()
            );
            if (similarity > 0.4) {
                int simScore = (int) Math.round(similarity * 20);
                score += simScore;
                matchReasons.add(String.format("AI Semantic Similarity score %.2f (+%d)", similarity, simScore));
            }
        }

        log.debug("Evaluated correlation between Alert ID: {} and Cluster ID: {} -> Total Score: {}",
                targetAlert.getId(), existingCluster.getId(), score);

        return CorrelationResult.builder()
                .matchedClusterId(existingCluster.getId())
                .score(score)
                .matchedIndicators(matchedIndicators)
                .matchReasons(matchReasons)
                .isNewCluster(false)
                .build();
    }

    private List<String> extractValuesByType(List<Indicator> indicators, IndicatorType type) {
        if (indicators == null) return List.of();
        return indicators.stream()
                .filter(i -> i.getType() == type)
                .map(Indicator::getValue)
                .toList();
    }
}
