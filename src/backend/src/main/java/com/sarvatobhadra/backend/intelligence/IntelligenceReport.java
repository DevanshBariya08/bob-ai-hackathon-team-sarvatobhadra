package com.sarvatobhadra.backend.intelligence;

import com.sarvatobhadra.backend.common.enums.SourceType;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * JPA Entity representing an ingested Intelligence Report or document (PDF, DOCX, TXT, OSINT feed).
 */
@Entity
@Table(name = "intelligence_reports")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IntelligenceReport {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 200)
    private String title;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    @Builder.Default
    private SourceType source = SourceType.INTEL_REPORT;

    @Column(columnDefinition = "TEXT", nullable = false)
    private String content;

    @Column(columnDefinition = "TEXT")
    private String summary;

    @Column(name = "file_type", length = 20)
    private String fileType;

    @Column(name = "file_path", length = 300)
    private String filePath;

    @Column(name = "cluster_id")
    private Long clusterId;

    @Column(name = "uploaded_at")
    @Builder.Default
    private LocalDateTime uploadedAt = LocalDateTime.now();
}
