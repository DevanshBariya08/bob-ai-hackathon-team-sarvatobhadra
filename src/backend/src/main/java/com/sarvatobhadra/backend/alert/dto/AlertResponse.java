package com.sarvatobhadra.backend.alert.dto;

import com.sarvatobhadra.backend.common.enums.Severity;
import com.sarvatobhadra.backend.common.enums.SourceType;
import com.sarvatobhadra.backend.indicator.Indicator;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Data Transfer Object for returning normalized alert information and associated indicators.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AlertResponse {

    private Long id;
    private SourceType source;
    private LocalDateTime timestamp;
    private Severity severity;
    private String eventType;
    private String description;
    private Long clusterId;
    private String target;
    private String threatActor;
    private List<Indicator> indicators;
    private LocalDateTime createdAt;
}
