package com.sarvatobhadra.backend.bluf;

import com.sarvatobhadra.backend.common.enums.Priority;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * JPA Entity representing an evidence-backed Bottom Line Up Front (BLUF) Threat Assessment Report.
 * Designed per PDF Section 10 specification.
 */
@Entity
@Table(name = "bluf_reports")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BlufReport {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "cluster_id", nullable = false)
    private Long clusterId;

    @Column(name = "threat_summary", nullable = false, length = 300)
    private String threatSummary;

    @Column(length = 20)
    @Builder.Default
    private String confidence = "HIGH"; // LOW, MEDIUM, HIGH

    @Column(name = "affected_target", length = 200)
    private String affectedTarget;

    @Column(name = "evidence_summary", columnDefinition = "TEXT")
    private String evidenceSummary;

    @Column(columnDefinition = "TEXT")
    private String assessment;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Priority priority;

    @Column(name = "analyst_review_status", length = 30)
    @Builder.Default
    private String analystReviewStatus = "REQUIRED"; // REQUIRED, COMPLETED, MODIFIED

    @Column(name = "generated_at")
    @Builder.Default
    private LocalDateTime generatedAt = LocalDateTime.now();
}
