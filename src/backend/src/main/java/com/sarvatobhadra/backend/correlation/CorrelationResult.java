package com.sarvatobhadra.backend.correlation;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

/**
 * Data object holding detailed correlation analysis output.
 * Details matching cluster ID, aggregate score, matched IOCs, and explainable rule breakdowns.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CorrelationResult {

    private Long matchedClusterId;
    private double score;
    @Builder.Default
    private List<String> matchedIndicators = new ArrayList<>();
    @Builder.Default
    private List<String> matchReasons = new ArrayList<>();
    private boolean isNewCluster;
}
