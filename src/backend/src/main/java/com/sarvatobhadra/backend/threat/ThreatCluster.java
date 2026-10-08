package com.sarvatobhadra.backend.threat;

import com.sarvatobhadra.backend.common.enums.Priority;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * JPA Entity representing a Correlated Threat Cluster.
 * Groups related alerts, sensor events, and intelligence reports into a unified threat subject.
 */
@Entity
@Table(name = "threat_clusters")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ThreatCluster {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 200)
    private String title;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(name = "correlation_score")
    private Double correlationScore;

    @Column(name = "threat_score")
    private Integer threatScore;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Priority priority;

    @Column(nullable = false, length = 30)
    @Builder.Default
    private String status = "OPEN"; // OPEN, UNDER_REVIEW, CONFIRMED, REJECTED

    @Column(name = "affected_target", length = 200)
    private String affectedTarget;

    @Column(name = "primary_actor", length = 100)
    private String primaryActor;

    @Column(name = "alert_count")
    @Builder.Default
    private Integer alertCount = 0;

    @Column(name = "report_count")
    @Builder.Default
    private Integer reportCount = 0;

    @Column(name = "created_at")
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "updated_at")
    @Builder.Default
    private LocalDateTime updatedAt = LocalDateTime.now();
}
