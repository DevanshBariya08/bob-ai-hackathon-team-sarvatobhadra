package com.sarvatobhadra.backend.alert;

import com.sarvatobhadra.backend.common.enums.Severity;
import com.sarvatobhadra.backend.common.enums.SourceType;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * JPA Entity representing a normalized cyber alert or sensor event.
 * Collects information from SIEM, Cyber Sensors, OSINT, or Reports.
 */
@Entity
@Table(name = "alerts")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Alert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private SourceType source;

    @Column(nullable = false)
    @Builder.Default
    private LocalDateTime timestamp = LocalDateTime.now();

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Severity severity;

    @Column(name = "event_type", length = 100)
    private String eventType;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(name = "raw_payload", columnDefinition = "TEXT")
    private String rawPayload;

    @Column(name = "cluster_id")
    private Long clusterId;

    @Column(length = 150)
    private String target;

    @Column(name = "threat_actor", length = 100)
    private String threatActor;

    @Column(name = "created_at")
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();
}
