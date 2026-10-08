package com.sarvatobhadra.backend.bluf;

import com.sarvatobhadra.backend.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * REST Controller for generating and retrieving Bottom Line Up Front (BLUF) threat assessments.
 */
@RestController
@RequestMapping("/bluf")
@RequiredArgsConstructor
public class BlufController {

    private final BlufService blufService;

    /**
     * Triggers RAG-based evidence retrieval and generates a new BLUF report for a threat cluster.
     * POST /bluf/generate/{clusterId}
     */
    @PostMapping("/generate/{clusterId}")
    public ResponseEntity<ApiResponse<BlufReport>> generateBluf(@PathVariable Long clusterId) {
        BlufReport report = blufService.generateBlufForCluster(clusterId);
        return ResponseEntity.ok(ApiResponse.success(report, "BLUF assessment generated successfully"));
    }

    /**                             
     * Retrieves existing BLUF report for a specific threat cluster.
     * GET /api/bluf/cluster/{clusterId}
     */
    @GetMapping("/cluster/{clusterId}")
    public ResponseEntity<ApiResponse<BlufReport>> getBlufByCluster(@PathVariable Long clusterId) {
        BlufReport report = blufService.getBlufByClusterId(clusterId);
        return ResponseEntity.ok(ApiResponse.success(report));
    }

    /**
     * Retrieves BLUF report by ID.
     * GET /api/bluf/{id}
     */
    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<BlufReport>> getBlufById(@PathVariable Long id) {
        BlufReport report = blufService.getBlufById(id);
        return ResponseEntity.ok(ApiResponse.success(report));
    }
}
