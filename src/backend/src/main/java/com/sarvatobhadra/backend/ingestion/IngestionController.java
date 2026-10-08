package com.sarvatobhadra.backend.ingestion;

import com.sarvatobhadra.backend.common.ApiResponse;
import com.sarvatobhadra.backend.common.enums.SourceType;
import com.sarvatobhadra.backend.intelligence.IntelligenceReport;
import com.sarvatobhadra.backend.threat.ThreatCluster;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.ArrayList;
import java.util.List;

/**
 * REST Controller providing multi-source data ingestion endpoints (SIEM JSON, Cyber Sensor, OSINT, PDF documents).
 */
@RestController
@RequestMapping("/ingest")
@RequiredArgsConstructor
public class IngestionController {

    private final IngestionService ingestionService;

    /**
     * Ingests a single JSON alert payload (SIEM, Cyber Sensor, OSINT).
     * POST /ingest/json
     */
    @PostMapping("/json")
    public ResponseEntity<ApiResponse<ThreatCluster>> ingestJson(
            @RequestBody String payload,
            @RequestParam(defaultValue = "SIEM") SourceType source
    ) {
        ThreatCluster cluster = ingestionService.ingestJsonAlert(payload, source);
        return ResponseEntity.ok(ApiResponse.success(cluster, "Data ingested and correlated successfully"));
    }

    /**
     * Ingests a multi-format document file (PDF, DOCX, TXT, CSV).
     * POST /ingest/file
     */
    @PostMapping("/file")
    public ResponseEntity<ApiResponse<IntelligenceReport>> ingestFile(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "title", required = false) String title
    ) {
        IntelligenceReport report = ingestionService.ingestFile(file, title);
        return ResponseEntity.ok(ApiResponse.success(report, "Intelligence report uploaded and parsed successfully"));
    }

    /**
     * Ingests multiple raw JSON alerts in batch.
     * POST /ingest/batch
     */
    @PostMapping("/batch")
    public ResponseEntity<ApiResponse<List<ThreatCluster>>> ingestBatch(
            @RequestBody List<String> payloads,
            @RequestParam(defaultValue = "SIEM") SourceType source
    ) {
        List<ThreatCluster> clusters = new ArrayList<>();
        for (String payload : payloads) {
            clusters.add(ingestionService.ingestJsonAlert(payload, source));
        }
        return ResponseEntity.ok(ApiResponse.success(clusters, "Batch ingestion completed successfully"));
    }
}
