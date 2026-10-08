package com.sarvatobhadra.backend.alert;

import com.sarvatobhadra.backend.common.enums.Severity;
import com.sarvatobhadra.backend.common.enums.SourceType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Spring Data JPA Repository for managing {@link Alert} entity database operations.
 */
@Repository
public interface AlertRepository extends JpaRepository<Alert, Long> {

    List<Alert> findByClusterId(Long clusterId);

    List<Alert> findBySeverity(Severity severity);

    List<Alert> findBySource(SourceType source);

    long countBySeverity(Severity severity);
}
