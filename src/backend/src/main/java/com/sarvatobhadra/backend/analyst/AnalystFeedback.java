package com.sarvatobhadra.backend.analyst;

import com.sarvatobhadra.backend.common.enums.FeedbackStatus;
import com.sarvatobhadra.backend.common.enums.Priority;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * JPA Entity representing Human-in-the-Loop Analyst Feedback as specified in PDF Section 11.
 * Stores analyst review decisions (Confirm / Reject / Modify) and training feedback.
 */
@Entity
@Table(name = "analyst_feedback")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AnalystFeedback {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "cluster_id", nullable = false)
    private Long clusterId;

    @Column(name = "bluf_id")
    private Long blufId;

    @Column(name = "analyst_username", nullable = false, length = 50)
    private String analystUsername;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private FeedbackStatus action; // CONFIRMED, REJECTED, MODIFIED

    @Enumerated(EnumType.STRING)
    @Column(name = "modified_priority", length = 20)
    private Priority modifiedPriority;

    @Column(columnDefinition = "TEXT")
    private String comments;

    @Column(name = "created_at")
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();
}
