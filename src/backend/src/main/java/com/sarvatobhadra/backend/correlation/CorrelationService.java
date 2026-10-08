package com.sarvatobhadra.backend.correlation;

import com.sarvatobhadra.backend.alert.Alert;
import com.sarvatobhadra.backend.alert.AlertRepository;
import com.sarvatobhadra.backend.common.enums.Priority;

import com.sarvatobhadra.backend.indicator.Indicator;
import com.sarvatobhadra.backend.indicator.IndicatorRepository;
import com.sarvatobhadra.backend.intelligence.IntelligenceReport;
import com.sarvatobhadra.backend.intelligence.ReportRepository;
import com.sarvatobhadra.backend.threat.ThreatCluster;
import com.sarvatobhadra.backend.threat.ThreatClusterRepository;
import com.sarvatobhadra.backend.threat.ThreatScoringService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Service orchestrating correlation for newly ingested alerts and reports.
 * Matches incoming events against existing open clusters or spawns a new correlated threat cluster.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CorrelationService {

    private final CorrelationEngine correlationEngine;
    private final ThreatClusterRepository threatClusterRepository;
    private final AlertRepository alertRepository;
    private final IndicatorRepository indicatorRepository;
    private final ReportRepository reportRepository;
    private final ThreatScoringService threatScoringService;

    /**
     * Correlates an ingested alert with existing threat clusters.
     * If correlation score >= 30, links to the highest matching cluster; otherwise creates a new cluster.
     */
    @Transactional
    public ThreatCluster correlateAlert(Alert alert, List<Indicator> alertIndicators) {
        log.info("Correlating incoming alert ID: {} ({})", alert.getId(), alert.getEventType());

        List<ThreatCluster> openClusters = threatClusterRepository.findAll();
        ThreatCluster bestMatchCluster = null;
        double maxScore = 0.0;
        List<String> bestReasons = new ArrayList<>();

        for (ThreatCluster candidateCluster : openClusters) {
            List<Alert> clusterAlerts = alertRepository.findByClusterId(candidateCluster.getId());
            List<Indicator> clusterIndicators = new ArrayList<>();
            for (Alert ca : clusterAlerts) {
                clusterIndicators.addAll(indicatorRepository.findByAlertId(ca.getId()));
            }

            CorrelationResult result = correlationEngine.evaluateCorrelation(
                    alert, alertIndicators, candidateCluster, clusterAlerts, clusterIndicators
            );

            if (result.getScore() > maxScore && result.getScore() >= 30.0) {
                maxScore = result.getScore();
                bestMatchCluster = candidateCluster;
                bestReasons = result.getMatchReasons();
            }
        }

        if (bestMatchCluster != null) {
            log.info("Alert ID: {} matched with existing Cluster ID: {} with score: {}",
                    alert.getId(), bestMatchCluster.getId(), maxScore);
            alert.setClusterId(bestMatchCluster.getId());
            alertRepository.save(alert);

            // Update cluster metrics
            List<Alert> updatedAlerts = alertRepository.findByClusterId(bestMatchCluster.getId());
            List<IntelligenceReport> reports = reportRepository.findByClusterId(bestMatchCluster.getId());
            int newThreatScore = threatScoringService.calculateThreatScore(bestMatchCluster, updatedAlerts, reports);
            Priority newPriority = threatScoringService.mapScoreToPriority(newThreatScore);

            bestMatchCluster.setAlertCount(updatedAlerts.size());
            bestMatchCluster.setCorrelationScore(maxScore);
            bestMatchCluster.setThreatScore(newThreatScore);
            bestMatchCluster.setPriority(newPriority);
            bestMatchCluster.setUpdatedAt(LocalDateTime.now());

            return threatClusterRepository.save(bestMatchCluster);
        } else {
            // Create a new Correlated Threat Cluster
            log.info("No matching cluster found for Alert ID: {}. Creating a new threat cluster.", alert.getId());
            String title = (alert.getEventType() != null ? alert.getEventType() : "Security Event") + " Cluster";
            if (alert.getTarget() != null) {
                title += " - Targeting " + alert.getTarget();
            }

            ThreatCluster newCluster = ThreatCluster.builder()
                    .title(title)
                    .description(alert.getDescription())
                    .correlationScore(30.0)
                    .threatScore(45)
                    .priority(Priority.MEDIUM)
                    .status("OPEN")
                    .affectedTarget(alert.getTarget() != null ? alert.getTarget() : "General Infrastructure")
                    .primaryActor(alert.getThreatActor())
                    .alertCount(1)
                    .reportCount(0)
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build();

            newCluster = threatClusterRepository.save(newCluster);
            alert.setClusterId(newCluster.getId());
            alertRepository.save(alert);

            return newCluster;
        }
    }
}
