package com.sarvatobhadra.backend.ingestion;

import com.sarvatobhadra.backend.alert.Alert;
import com.sarvatobhadra.backend.alert.AlertRepository;
import com.sarvatobhadra.backend.client.NlpClient;
import com.sarvatobhadra.backend.common.enums.Severity;
import com.sarvatobhadra.backend.common.enums.SourceType;
import com.sarvatobhadra.backend.correlation.CorrelationService;
import com.sarvatobhadra.backend.indicator.Indicator;
import com.sarvatobhadra.backend.indicator.IndicatorService;
import com.sarvatobhadra.backend.intelligence.IntelligenceReport;
import com.sarvatobhadra.backend.intelligence.ReportService;
import com.sarvatobhadra.backend.threat.ThreatCluster;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Service managing multi-source data ingestion pipeline (SIEM JSON, Cyber Sensor logs, OSINT feeds, PDF/DOCX files).
 * Coordinates text extraction, normalization, entity extraction, repository saving, and threat correlation.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class IngestionService {

    private final FileParser fileParser;
    private final DataNormalizer dataNormalizer;
    private final NlpClient nlpClient;
    private final AlertRepository alertRepository;
    private final IndicatorService indicatorService;
    private final ReportService reportService;
    private final CorrelationService correlationService;

    /**
     * Ingests a raw JSON alert payload or text message.
     */
    @Transactional
    public ThreatCluster ingestJsonAlert(String jsonPayload, SourceType source) {
        log.info("Processing JSON alert ingestion from source: {}", source);
        Alert normalizedAlert = dataNormalizer.normalizeAlert(jsonPayload, source);
        normalizedAlert = alertRepository.save(normalizedAlert);

        // Extract indicators using NlpClient
        NlpClient.ExtractedEntities entities = nlpClient.extractEntities(normalizedAlert.getDescription());
        List<Indicator> indicators = saveExtractedIndicators(entities, normalizedAlert.getId(), null);

        // Trigger hybrid correlation
        return correlationService.correlateAlert(normalizedAlert, indicators);
    }

    /**
     * Ingests a multi-format document file (PDF, DOCX, TXT, CSV).
     */
    @Transactional
    public IntelligenceReport ingestFile(MultipartFile file, String title) {
        log.info("Processing file upload ingestion: {}", file.getOriginalFilename());
        String extractedText = fileParser.parseFile(file);

        NlpClient.ExtractedEntities entities = nlpClient.extractEntities(extractedText);

        IntelligenceReport report = IntelligenceReport.builder()
                .title(title != null ? title : file.getOriginalFilename())
                .source(SourceType.INTEL_REPORT)
                .content(extractedText)
                .summary(entities.getSummary())
                .fileType(getFileExtension(file.getOriginalFilename()))
                .filePath(file.getOriginalFilename())
                .uploadedAt(LocalDateTime.now())
                .build();

        report = reportService.saveReport(report);
        saveExtractedIndicators(entities, null, report.getId());

        String severity = entities != null ? String.valueOf(entities.getPredictedSeverity()) : null;

        if (severity == null || severity.isBlank()) {
            severity = extractSeverityFromText(extractedText);
        }

        Alert reportAlert = Alert.builder()
                .source(SourceType.INTEL_REPORT)
                .timestamp(LocalDateTime.now())
                .severity(Severity.valueOf(severity))
                .eventType("INTEL_DOCUMENT_ANALYSIS")
                .description(extractedText)
                .target(entities != null ? entities.getTargetSystem() : null)
                .threatActor(entities != null ? entities.getThreatActor() : null)
                .createdAt(LocalDateTime.now())
                .build();

        reportAlert = alertRepository.save(reportAlert);
        List<Indicator> reportIndicators = indicatorService.getIndicatorsByReportId(report.getId());
        ThreatCluster cluster = correlationService.correlateAlert(reportAlert, reportIndicators);

        report.setClusterId(cluster.getId());
        return reportService.saveReport(report);
    }

    private static final java.util.regex.Pattern SEVERITY_PATTERN = java.util.regex.Pattern.compile(
            "(?i)severity\\s*[:\\-=]?\\s*(critical|high|medium|low|info)");

    private String extractSeverityFromText(String text) {
        if (text != null) {
            java.util.regex.Matcher m = SEVERITY_PATTERN.matcher(text);
            if (m.find()) {
                return m.group(1).toUpperCase();
            }
            String lower = text.toLowerCase();
            if (lower.contains("critical")) return "CRITICAL";
            if (lower.contains("high")) return "HIGH";
            if (lower.contains("medium")) return "MEDIUM";
            if (lower.contains("low")) return "LOW";
        }
        return String.valueOf(Severity.MEDIUM); // safe default
    }

    private List<Indicator> saveExtractedIndicators(NlpClient.ExtractedEntities entities, Long alertId, Long reportId) {
        List<Indicator> savedList = new ArrayList<>();
        if (entities != null && entities.getIndicators() != null) {
            for (NlpClient.ExtractedIndicator ext : entities.getIndicators()) {
                Indicator saved = indicatorService.saveIndicator(
                        ext.getType(),
                        ext.getValue(),
                        alertId,
                        reportId,
                        ext.getConfidence()
                );
                savedList.add(saved);
            }
        }
        return savedList;
    }

    private String getFileExtension(String filename) {
        if (filename != null && filename.contains(".")) {
            return filename.substring(filename.lastIndexOf(".") + 1).toUpperCase();
        }
        return "TXT";
    }
}
