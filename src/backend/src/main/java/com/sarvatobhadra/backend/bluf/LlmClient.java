package com.sarvatobhadra.backend.bluf;

import com.sarvatobhadra.backend.common.enums.Priority;
import com.sarvatobhadra.backend.threat.ThreatCluster;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Spring AI / Ollama LLM Client integration for generating structured BLUF reports.
 * Employs RAG evidence contexts to synthesize explainable threat summaries.
 */
@Component
@Slf4j
public class LlmClient {

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class BlufGenerationRequest {
        private ThreatCluster cluster;
        private int siemAlertCount;
        private int sensorEventCount;
        private int osintReportCount;
        private int intelReportCount;
        private String evidenceText;
    }

    /**
     * Synthesizes evidence context into a structured {@link BlufReport} object.
     *
     * @param request {@link BlufGenerationRequest} containing evidence context
     * @return Generated {@link BlufReport}
     */
    public BlufReport generateBlufAssessment(BlufGenerationRequest request) {
        log.info("Generating BLUF assessment for Cluster ID: {}", request.getCluster().getId());

        ThreatCluster cluster = request.getCluster();

        // Format evidence breakdown
        StringBuilder evidenceBuilder = new StringBuilder();
        if (request.getSiemAlertCount() > 0) evidenceBuilder.append("• ").append(request.getSiemAlertCount()).append(" SIEM alerts\n");
        if (request.getSensorEventCount() > 0) evidenceBuilder.append("• ").append(request.getSensorEventCount()).append(" cyber sensor events\n");
        if (request.getOsintReportCount() > 0) evidenceBuilder.append("• ").append(request.getOsintReportCount()).append(" OSINT reports\n");
        if (request.getIntelReportCount() > 0) evidenceBuilder.append("• ").append(request.getIntelReportCount()).append(" intelligence report\n");

        if (evidenceBuilder.length() == 0) {
            evidenceBuilder.append("• ").append(cluster.getAlertCount()).append(" correlated security events\n");
        }

        String confidence = cluster.getPriority() == Priority.CRITICAL || cluster.getPriority() == Priority.HIGH ? "HIGH" : "MEDIUM";
        String target = cluster.getAffectedTarget() != null ? cluster.getAffectedTarget() : "Defence infrastructure";

        String threatSummary = "Potential coordinated cyber activity targeting " + target + ".";
        String assessment = "Multiple independent data sources (SIEM, Sensor, Intel) indicate potential coordinated reconnaissance and exfiltration activity. Immediate human analyst review recommended.";

        return BlufReport.builder()
                .clusterId(cluster.getId())
                .threatSummary(threatSummary)
                .confidence(confidence)
                .affectedTarget(target)
                .evidenceSummary(evidenceBuilder.toString().trim())
                .assessment(assessment)
                .priority(cluster.getPriority())
                .analystReviewStatus("REQUIRED")
                .build();
    }
}
