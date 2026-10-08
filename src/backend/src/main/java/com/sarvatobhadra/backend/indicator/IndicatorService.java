package com.sarvatobhadra.backend.indicator;

import com.sarvatobhadra.backend.common.enums.IndicatorType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Service managing indicator extraction persistence and query lookups.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class IndicatorService {

    private final IndicatorRepository indicatorRepository;

    /**
     * Persists a new indicator associated with an alert or intelligence report.
     */
    @Transactional
    public Indicator saveIndicator(IndicatorType type, String value, Long alertId, Long reportId, Double confidence) {
        log.info("Saving indicator type: {}, value: {}, alertId: {}, reportId: {}", type, value, alertId, reportId);
        Indicator indicator = Indicator.builder()
                .type(type)
                .value(value)
                .alertId(alertId)
                .reportId(reportId)
                .confidence(confidence != null ? confidence : 0.90)
                .createdAt(LocalDateTime.now())
                .build();
        return indicatorRepository.save(indicator);
    }

    public List<Indicator> getIndicatorsByAlertId(Long alertId) {
        return indicatorRepository.findByAlertId(alertId);
    }

    public List<Indicator> getIndicatorsByReportId(Long reportId) {
        return indicatorRepository.findByReportId(reportId);
    }

    public List<Indicator> getIndicatorsByValue(String value) {
        return indicatorRepository.findByValue(value);
    }

    public List<Indicator> getAllIndicators() {
        return indicatorRepository.findAll();
    }
}
