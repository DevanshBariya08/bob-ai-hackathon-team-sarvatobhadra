package com.sarvatobhadra.backend.bluf;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Spring Data JPA Repository for managing {@link BlufReport} entities.
 */
@Repository
public interface BlufRepository extends JpaRepository<BlufReport, Long> {

    Optional<BlufReport> findByClusterId(Long clusterId);
}
