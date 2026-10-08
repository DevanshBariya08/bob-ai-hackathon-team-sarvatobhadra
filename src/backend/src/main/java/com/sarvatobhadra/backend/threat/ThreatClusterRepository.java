package com.sarvatobhadra.backend.threat;

import com.sarvatobhadra.backend.common.enums.Priority;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Spring Data JPA Repository for managing {@link ThreatCluster} database queries.
 */
@Repository
public interface ThreatClusterRepository extends JpaRepository<ThreatCluster, Long> {

    List<ThreatCluster> findByPriority(Priority priority);

    List<ThreatCluster> findByStatus(String status);

    long countByPriority(Priority priority);
}
