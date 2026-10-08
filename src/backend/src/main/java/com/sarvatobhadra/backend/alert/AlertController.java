package com.sarvatobhadra.backend.alert;

import com.sarvatobhadra.backend.alert.dto.AlertResponse;
import com.sarvatobhadra.backend.common.ApiResponse;
import com.sarvatobhadra.backend.common.enums.Severity;
import com.sarvatobhadra.backend.common.enums.SourceType;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/alerts")
@RequiredArgsConstructor
public class AlertController {

    private final AlertService alertService;

    /**
     * Retrieves all ingested alerts.
     * GET /api/alerts
     */
    @GetMapping
    public ResponseEntity<ApiResponse<List<AlertResponse>>> getAllAlerts() {
        return ResponseEntity.ok(ApiResponse.success(alertService.getAllAlerts()));
    }

    /**
     * Retrieves alert details by ID.
     * GET /api/alerts/{id}
     */
    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<AlertResponse>> getAlertById(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.success(alertService.getAlertById(id)));
    }


    @GetMapping("/cluster/{clusterId}")
    public ResponseEntity<ApiResponse<List<AlertResponse>>> getAlertsByCluster(@PathVariable Long clusterId) {
        return ResponseEntity.ok(ApiResponse.success(alertService.getAlertsByCluster(clusterId)));
    }


    @GetMapping("/severity/{severity}")
    public ResponseEntity<ApiResponse<List<AlertResponse>>> getAlertsBySeverity(@PathVariable Severity severity) {
        return ResponseEntity.ok(ApiResponse.success(alertService.getAlertsBySeverity(severity)));
    }


    @GetMapping("/source/{source}")
    public ResponseEntity<ApiResponse<List<AlertResponse>>> getAlertsBySource(@PathVariable SourceType source) {
        return ResponseEntity.ok(ApiResponse.success(alertService.getAlertsBySource(source)));
    }

    
    @GetMapping("/stats")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getAlertStats() {
        return ResponseEntity.ok(ApiResponse.success(alertService.getAlertStatistics(), "Alert statistics retrieved"));
    }
}
