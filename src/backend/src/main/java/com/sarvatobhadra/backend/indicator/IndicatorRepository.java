package com.sarvatobhadra.backend.indicator;

import com.sarvatobhadra.backend.common.enums.IndicatorType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Spring Data JPA Repository for {@link Indicator} management.
 */
@Repository
public interface IndicatorRepository extends JpaRepository<Indicator, Long> {

    List<Indicator> findByValue(String value);

    List<Indicator> findByType(IndicatorType type);

    List<Indicator> findByAlertId(Long alertId);

    List<Indicator> findByReportId(Long reportId);

    List<Indicator> findByValueIn(List<String> values);
}
