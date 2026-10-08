package com.sarvatobhadra.backend.common.enums;

/**
 * Enumeration representing the priority category of a correlated threat cluster or BLUF report.
 * Derived from the hybrid correlation & scoring engine (0-30: LOW, 31-60: MEDIUM, 61-80: HIGH, 81-100: CRITICAL).
 */
public enum Priority {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}
