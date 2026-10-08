package com.sarvatobhadra.backend.analyst;

import com.sarvatobhadra.backend.common.ApiResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * REST Controller exposing human-in-the-loop analyst feedback submission and lookup endpoints.
 */
@RestController
@RequestMapping("/analyst")
@RequiredArgsConstructor
public class AnalystController {

    private final AnalystService analystService;

    /**
     * Submits human analyst feedback (Confirm, Reject, Modify) for a threat cluster and BLUF assessment.
     * POST /api/analyst/feedback
     */
    @PostMapping("/feedback")
    public ResponseEntity<ApiResponse<AnalystFeedback>> submitFeedback(@Valid @RequestBody AnalystFeedback feedback) {
        AnalystFeedback saved = analystService.submitFeedback(feedback);
        return ResponseEntity.ok(ApiResponse.success(saved, "Analyst feedback recorded successfully"));
    }

    /**
     * Retrieves feedback records for a specific threat cluster.
     * GET /api/analyst/feedback/cluster/{clusterId}
     */
    @GetMapping("/feedback/cluster/{clusterId}")
    public ResponseEntity<ApiResponse<List<AnalystFeedback>>> getFeedbackByCluster(@PathVariable Long clusterId) {
        return ResponseEntity.ok(ApiResponse.success(analystService.getFeedbackByCluster(clusterId)));
    }

    /**
     * Retrieves all analyst feedback history.
     * GET /api/analyst/feedback
     */
    @GetMapping("/feedback")
    public ResponseEntity<ApiResponse<List<AnalystFeedback>>> getAllFeedback() {
        return ResponseEntity.ok(ApiResponse.success(analystService.getAllFeedback()));
    }
}
