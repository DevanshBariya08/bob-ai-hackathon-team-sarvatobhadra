package com.sarvatobhadra.backend.intelligence;

import com.sarvatobhadra.backend.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * REST Controller for querying and managing intelligence reports.
 */
@RestController
@RequestMapping("/reports")
@RequiredArgsConstructor
public class ReportController {

    private final ReportService reportService;

    /**
     * Retrieves all ingested intelligence reports.
     * GET /api/reports
     */
    @GetMapping
    public ResponseEntity<ApiResponse<List<IntelligenceReport>>> getAllReports() {
        return ResponseEntity.ok(ApiResponse.success(reportService.getAllReports()));
    }

    /**
     * Retrieves report by ID.
     * GET /api/reports/{id}
     */
    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<IntelligenceReport>> getReportById(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.success(reportService.getReportById(id)));
    }

    /**
     * Retrieves reports associated with a threat cluster.
     * GET /api/reports/cluster/{clusterId}
     */
    @GetMapping("/cluster/{clusterId}")
    public ResponseEntity<ApiResponse<List<IntelligenceReport>>> getReportsByCluster(@PathVariable Long clusterId) {
        return ResponseEntity.ok(ApiResponse.success(reportService.getReportsByCluster(clusterId)));
    }
}
