package com.sarvatobhadra.backend.indicator;

import com.sarvatobhadra.backend.common.enums.IndicatorType;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * JPA Entity representing an Indicator of Compromise (IOC) or extracted threat entity.
 * Links extracted artifacts (IPs, Domains, Malware, Threat Actors) to raw Alerts or Intel Reports.
 */
@Entity
@Table(name = "indicators", indexes = {
        @Index(name = "idx_indicator_val_type", columnList = "indicator_value, type")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Indicator {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private IndicatorType type;

    @Column(name = "indicator_value", nullable = false, length = 255)
    private String value;

    @Column(name = "alert_id")
    private Long alertId;

    @Column(name = "report_id")
    private Long reportId;

    @Builder.Default
    private Double confidence = 0.90;

    @Column(name = "created_at")
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();
}
