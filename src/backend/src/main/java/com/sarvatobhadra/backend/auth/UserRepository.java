package com.sarvatobhadra.backend.auth;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Spring Data JPA Repository for managing {@link UserEntity} persistence.
 */
@Repository
public interface UserRepository extends JpaRepository<UserEntity, Long> {

    /**
     * Finds a user entity by unique username.
     *
     * @param username User login name
     * @return Optional containing user entity if present
     */
    Optional<UserEntity> findByUsername(String username);

    /**
     * Checks if a user already exists with the given username.
     *
     * @param username Username to verify
     * @return true if username exists
     */
    boolean existsByUsername(String username);
}
