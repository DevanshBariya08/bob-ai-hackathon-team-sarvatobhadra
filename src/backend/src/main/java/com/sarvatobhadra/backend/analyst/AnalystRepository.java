package com.sarvatobhadra.backend.analyst;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Spring Data JPA Repository for managing {@link AnalystFeedback} entities.
 */
@Repository
public interface AnalystRepository extends JpaRepository<AnalystFeedback, Long> {

    List<AnalystFeedback> findByClusterId(Long clusterId);

    List<AnalystFeedback> findByAnalystUsername(String username);
}
