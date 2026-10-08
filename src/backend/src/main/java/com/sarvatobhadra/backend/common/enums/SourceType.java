package com.sarvatobhadra.backend.common.enums;

/**
 * Enumeration representing multi-source ingestion types accepted by the platform.
 * Supports SIEM alerts, Cyber Sensor events, OSINT feeds, and Intelligence Reports (PDF/DOCX/TXT/CSV).
 */
public enum SourceType {
    SIEM,
    SENSOR,
    OSINT,
    INTEL_REPORT
}
