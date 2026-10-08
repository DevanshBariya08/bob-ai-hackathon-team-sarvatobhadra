package com.sarvatobhadra.backend.threat;

import com.sarvatobhadra.backend.common.ApiResponse;
import com.sarvatobhadra.backend.common.enums.Priority;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * REST Controller exposing management endpoints for threat clusters, scoring, and priority breakdown.
 */
@RestController
@RequestMapping("/threats")
@RequiredArgsConstructor
public class ThreatController {

    private final ThreatService threatService;

    /**
     * Retrieves all correlated threat clusters.
     * GET /threats/clusters
     */
    @GetMapping("/clusters")
    public ResponseEntity<ApiResponse<List<ThreatCluster>>> getAllClusters() {
        return ResponseEntity.ok(ApiResponse.success(threatService.getAllClusters()));
    }

    /**
     * Retrieves threat cluster details by ID.
     * GET /threats/clusters/{id}
     */
    @GetMapping("/clusters/{id}")
    public ResponseEntity<ApiResponse<ThreatCluster>> getClusterById(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.success(threatService.getClusterById(id)));
    }

    /**
     * Filters threat clusters by priority level (LOW, MEDIUM, HIGH, CRITICAL).
     * GET /api/threats/priority/{priority}
     */
    @GetMapping("/priority/{priority}")
    public ResponseEntity<ApiResponse<List<ThreatCluster>>> getClustersByPriority(@PathVariable Priority priority) {
        return ResponseEntity.ok(ApiResponse.success(threatService.getClustersByPriority(priority)));
    }

    /**
     * Retrieves summary dashboard metrics for threat cluster priority distributions.
     * GET /api/threats/dashboard/stats
     */
    @GetMapping("/dashboard/stats")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getDashboardStats() {
        return ResponseEntity.ok(ApiResponse.success(threatService.getDashboardStats(), "Dashboard statistics retrieved"));
    }

    /**
     * Forces re-scoring and prioritization calculation for a specific threat cluster.
     * POST /api/threats/re-score/{clusterId}
     */
    @PostMapping("/re-score/{clusterId}")
    public ResponseEntity<ApiResponse<ThreatCluster>> reScoreCluster(@PathVariable Long clusterId) {
        ThreatCluster updatedCluster = threatService.reScoreCluster(clusterId);
        return ResponseEntity.ok(ApiResponse.success(updatedCluster, "Cluster threat score recalculated"));
    }
}
