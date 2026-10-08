package com.sarvatobhadra.backend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Main Spring Boot Application Entry Point for Threat Intelligence Correlation Platform Backend.
 * Initializes component scanning, auto-configuration, Spring Data JPA repositories,
 * security filters, and Flyway database migrations.
 */
@SpringBootApplication
public class BackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(BackendApplication.class, args);
	}

}
