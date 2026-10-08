package com.sarvatobhadra.backend.bluf;

import com.sarvatobhadra.backend.alert.Alert;
import com.sarvatobhadra.backend.alert.AlertRepository;
import com.sarvatobhadra.backend.common.enums.SourceType;
import com.sarvatobhadra.backend.intelligence.IntelligenceReport;
import com.sarvatobhadra.backend.intelligence.ReportRepository;
import com.sarvatobhadra.backend.threat.ThreatCluster;
import com.sarvatobhadra.backend.threat.ThreatClusterRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Service orchestrating RAG-based Evidence Retrieval and BLUF Assessment generation.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class BlufService {

    private final BlufRepository blufRepository;
    private final ThreatClusterRepository threatClusterRepository;
    private final AlertRepository alertRepository;
    private final ReportRepository reportRepository;
    private final LlmClient llmClient;

    /**
     * Executes RAG evidence retrieval for cluster alerts/reports and synthesizes BLUF assessment.
     *
     * @param clusterId Target threat cluster ID
     * @return Generated and persisted {@link BlufReport}
     */
    @Transactional
    public BlufReport generateBlufForCluster(Long clusterId) {
        log.info("Executing RAG evidence retrieval for cluster ID: {}", clusterId);

        ThreatCluster cluster = threatClusterRepository.findById(clusterId)
                .orElseThrow(() -> new RuntimeException("Threat Cluster not found with ID: " + clusterId));

        List<Alert> alerts = alertRepository.findByClusterId(clusterId);
        List<IntelligenceReport> reports = reportRepository.findByClusterId(clusterId);

        int siemCount = (int) alerts.stream().filter(a -> a.getSource() == SourceType.SIEM).count();
        int sensorCount = (int) alerts.stream().filter(a -> a.getSource() == SourceType.SENSOR).count();
        int osintCount = (int) alerts.stream().filter(a -> a.getSource() == SourceType.OSINT).count();
        int intelCount = reports.size();

        StringBuilder evidenceText = new StringBuilder();
        
        for (Alert a : alerts) {
            evidenceText.append("Alert: ").append(a.getDescription()).append("\n");
        }
        for (IntelligenceReport r : reports) {
            evidenceText.append("Report: ").append(r.getSummary() != null ? r.getSummary() : r.getTitle()).append("\n");
        }

        LlmClient.BlufGenerationRequest request = LlmClient.BlufGenerationRequest.builder()
                .cluster(cluster)
                .siemAlertCount(siemCount)
                .sensorEventCount(sensorCount)
                .osintReportCount(osintCount)
                .intelReportCount(intelCount)
                .evidenceText(evidenceText.toString())
                .build();

        BlufReport blufReport = llmClient.generateBlufAssessment(request);

        // Replace existing BLUF if generated previously
        blufRepository.findByClusterId(clusterId).ifPresent(existing -> blufReport.setId(existing.getId()));

        return blufRepository.save(blufReport);
    }

    public BlufReport getBlufByClusterId(Long clusterId) {
        return blufRepository.findByClusterId(clusterId)
                .orElseGet(() -> generateBlufForCluster(clusterId));
    }

    public BlufReport getBlufById(Long id) {
        return blufRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("BLUF Report not found with ID: " + id));
    }

    @Transactional
    public BlufReport saveBluf(BlufReport blufReport) {
        return blufRepository.save(blufReport);
    }
}
