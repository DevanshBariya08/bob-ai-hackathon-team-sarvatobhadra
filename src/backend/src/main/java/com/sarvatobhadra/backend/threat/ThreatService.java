package com.sarvatobhadra.backend.threat;

import com.sarvatobhadra.backend.alert.Alert;
import com.sarvatobhadra.backend.alert.AlertRepository;
import com.sarvatobhadra.backend.common.enums.Priority;
import com.sarvatobhadra.backend.intelligence.IntelligenceReport;
import com.sarvatobhadra.backend.intelligence.ReportRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Service managing threat clusters, priority re-scoring, and dashboard summary metrics.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ThreatService {

    private final ThreatClusterRepository threatClusterRepository;
    private final AlertRepository alertRepository;
    private final ReportRepository reportRepository;
    private final ThreatScoringService threatScoringService;

    public List<ThreatCluster> getAllClusters() {
        return threatClusterRepository.findAll();
    }

    public ThreatCluster getClusterById(Long id) {
        return threatClusterRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Threat Cluster not found with ID: " + id));
    }

    public List<ThreatCluster> getClustersByPriority(Priority priority) {
        return threatClusterRepository.findByPriority(priority);
    }

    /**
     * Calculates cluster statistics breakdown for executive dashboard charts.
     */
    public Map<String, Object> getDashboardStats() {
        Map<String, Object> stats = new HashMap<>();
        long totalClusters = threatClusterRepository.count();

        stats.put("totalClusters", totalClusters);
        stats.put("critical", threatClusterRepository.countByPriority(Priority.CRITICAL));
        stats.put("high", threatClusterRepository.countByPriority(Priority.HIGH));
        stats.put("medium", threatClusterRepository.countByPriority(Priority.MEDIUM));
        stats.put("low", threatClusterRepository.countByPriority(Priority.LOW));

        return stats;
    }

    /**
     * Recalculates threat score and updates priority for an existing cluster.
     */
    @Transactional
    public ThreatCluster reScoreCluster(Long clusterId) {
        ThreatCluster cluster = getClusterById(clusterId);
        List<Alert> alerts = alertRepository.findByClusterId(clusterId);
        List<IntelligenceReport> reports = reportRepository.findByClusterId(clusterId);

        int newScore = threatScoringService.calculateThreatScore(cluster, alerts, reports);
        Priority newPriority = threatScoringService.mapScoreToPriority(newScore);

        cluster.setThreatScore(newScore);
        cluster.setPriority(newPriority);
        cluster.setAlertCount(alerts.size());
        cluster.setReportCount(reports.size());
        cluster.setUpdatedAt(LocalDateTime.now());

        log.info("Re-scored Threat Cluster ID: {} -> Score: {}, Priority: {}", clusterId, newScore, newPriority);
        return threatClusterRepository.save(cluster);
    }

    @Transactional
    public ThreatCluster saveCluster(ThreatCluster cluster) {
        return threatClusterRepository.save(cluster);
    }
}
