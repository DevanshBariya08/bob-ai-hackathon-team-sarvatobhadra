package com.sarvatobhadra.backend.intelligence;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Spring Data JPA Repository for {@link IntelligenceReport}.
 */
@Repository
public interface ReportRepository extends JpaRepository<IntelligenceReport, Long> {

    List<IntelligenceReport> findByClusterId(Long clusterId);

    List<IntelligenceReport> findByTitleContainingIgnoreCase(String keyword);
}
