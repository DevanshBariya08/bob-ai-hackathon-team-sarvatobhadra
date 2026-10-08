package com.sarvatobhadra.backend.alert;

import com.sarvatobhadra.backend.alert.dto.AlertResponse;
import com.sarvatobhadra.backend.common.enums.Severity;
import com.sarvatobhadra.backend.common.enums.SourceType;
import com.sarvatobhadra.backend.indicator.Indicator;
import com.sarvatobhadra.backend.indicator.IndicatorRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Service managing alert retrieval, querying, statistical aggregation, and DTO conversion.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AlertService {

    private final AlertRepository alertRepository;
    private final IndicatorRepository indicatorRepository;

    public List<AlertResponse> getAllAlerts() {
        return alertRepository.findAll().stream()
                .map(this::toResponse)
                .toList();
    }

    public AlertResponse getAlertById(Long id) {
        Alert alert = alertRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Alert not found with ID: " + id));
        return toResponse(alert);
    }

    public List<AlertResponse> getAlertsByCluster(Long clusterId) {
        return alertRepository.findByClusterId(clusterId).stream()
                .map(this::toResponse)
                .toList();
    }

    public List<AlertResponse> getAlertsBySeverity(Severity severity) {
        return alertRepository.findBySeverity(severity).stream()
                .map(this::toResponse)
                .toList();
    }

    public List<AlertResponse> getAlertsBySource(SourceType source) {
        return alertRepository.findBySource(source).stream()
                .map(this::toResponse)
                .toList();
    }

    /**
     * Calculates total alert count and severity distribution breakdown for executive dashboard rendering.
     */
    public Map<String, Object> getAlertStatistics() {
        Map<String, Object> stats = new HashMap<>();
        long totalAlerts = alertRepository.count();

        stats.put("totalAlerts", totalAlerts);
        stats.put("critical", alertRepository.countBySeverity(Severity.CRITICAL));
        stats.put("high", alertRepository.countBySeverity(Severity.HIGH));
        stats.put("medium", alertRepository.countBySeverity(Severity.MEDIUM));
        stats.put("low", alertRepository.countBySeverity(Severity.LOW));

        return stats;
    }

    @Transactional
    public Alert saveAlert(Alert alert) {
        return alertRepository.save(alert);
    }

    private AlertResponse toResponse(Alert alert) {
        List<Indicator> indicators = indicatorRepository.findByAlertId(alert.getId());
        return AlertResponse.builder()
                .id(alert.getId())
                .source(alert.getSource())
                .timestamp(alert.getTimestamp())
                .severity(alert.getSeverity())
                .eventType(alert.getEventType())
                .description(alert.getDescription())
                .clusterId(alert.getClusterId())
                .target(alert.getTarget())
                .threatActor(alert.getThreatActor())
                .indicators(indicators)
                .createdAt(alert.getCreatedAt())
                .build();
    }
}
