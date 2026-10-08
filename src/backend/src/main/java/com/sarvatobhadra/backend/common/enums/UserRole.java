package com.sarvatobhadra.backend.common.enums;

/**
 * Enumeration representing user security roles for Role-Based Access Control (RBAC).
 * ADMIN users manage system configuration, while ANALYST users review alerts and BLUF reports.
 */
public enum UserRole {
    ROLE_ADMIN,
    ROLE_ANALYST
}
