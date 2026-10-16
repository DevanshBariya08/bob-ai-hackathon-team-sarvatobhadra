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
import java.util.regex.Pattern;

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
        normalizedAlert = alertRepository.save(normalizedAlert); // it save the alert

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
        log.info("extracted text from file {}",extractedText.length());

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

        // Severity: NLP value first, then fall back to text extraction
        String severity = null; // set from NLP if your model returns one
        if (severity == null || severity.isBlank() || severity.equalsIgnoreCase("null")) {
            severity = extractSeverityFromText(extractedText);
        }
        severity = severity.trim().toUpperCase();

        // Target: NLP value first, then fall back to text extraction
        String target = entities != null ? entities.getTargetSystem() : null;
        if (isBlankOrNull(target)) {
            target = extractFieldFromText(extractedText, TARGET_PATTERN, null);
        }

        // Threat actor: NLP value first, then fall back to text extraction
        String threatActor = null;
        if (isBlankOrNull(threatActor)) {
            threatActor = extractFieldFromText(extractedText, THREAT_ACTOR_PATTERN, null);
        }

        // Event type: extracted from text, defaulting to the generic label
        String eventType = extractFieldFromText(extractedText, EVENT_TYPE_PATTERN, "INTEL_DOCUMENT_ANALYSIS");

        Alert reportAlert = Alert.builder()
                .source(SourceType.INTEL_REPORT)
                .timestamp(LocalDateTime.now())
                .severity(Severity.valueOf(severity))
                .eventType(eventType)
                .description(extractedText)
                .target(target)
                .threatActor(threatActor)
                .createdAt(LocalDateTime.now())
                .build();

        reportAlert = alertRepository.save(reportAlert);
        List<Indicator> reportIndicators = indicatorService.getIndicatorsByReportId(report.getId());
        ThreatCluster cluster = correlationService.correlateAlert(reportAlert, reportIndicators);

        report.setClusterId(cluster.getId());
        return reportService.saveReport(report);
    }

    private static final Pattern SEVERITY_PATTERN = Pattern.compile(
            "(?im)\\b(?:threat\\s+)?severity\\b\\s*[:=\\-]?\\s*" +
                    "(CRITICAL|HIGH|MEDIUM|MODERATE|LOW|INFO(?:RMATIONAL)?)\\b"
    );

    private static final Pattern EVENT_TYPE_PATTERN = Pattern.compile(
            "(?im)\\b(?:event\\s*type|attack\\s*type|event\\s*category)\\b\\s*[:=\\-]?\\s*(.+)"
    );

    private static final Pattern TARGET_PATTERN = Pattern.compile(
            "(?im)\\b(?:target(?:\\s*system)?|targeted\\s*system|victim|affected\\s*system)\\b\\s*[:=\\-]?\\s*(.+)"
    );

    private static final Pattern THREAT_ACTOR_PATTERN = Pattern.compile(
            "(?im)\\b(?:threat\\s*actor|attacker|actor\\s*name|adversary)\\b\\s*[:=\\-]?\\s*(.+)"
    );

    private String extractSeverityFromText(String text) {

        if (text == null || text.isBlank()) {
            return Severity.MEDIUM.name();
        }

        java.util.regex.Matcher matcher =
                SEVERITY_PATTERN.matcher(text);

        // First, look for an explicitly declared severity.
        if (matcher.find()) {
            return matcher.group(1).toUpperCase();
        }

        // If no severity is specified, use a safe default.
        return Severity.MEDIUM.name();
    }

    /**
     * Generic regex-based field extractor. Returns the first match's captured value,
     * cleaned up, or the supplied default if nothing is found.
     */
    private String extractFieldFromText(String text, Pattern pattern, String defaultValue) {
        if (text == null || text.isBlank()) {
            return defaultValue;
        }

        java.util.regex.Matcher matcher = pattern.matcher(text);
        if (matcher.find()) {
            String value = matcher.group(1)
                    .trim()
                    .replaceAll("^[\"'`]+|[\"'`]+$", "")   // strip surrounding quotes
                    .replaceAll("[.,;]+$", "")             // strip trailing punctuation
                    .trim();

            if (!value.isEmpty()) {
                // Guard against runaway captures (column-sized DB fields)
                return value.length() > 255 ? value.substring(0, 255) : value;
            }
        }
        return defaultValue;
    }

    private boolean isBlankOrNull(String value) {
        return value == null || value.isBlank() || value.equalsIgnoreCase("null");
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
