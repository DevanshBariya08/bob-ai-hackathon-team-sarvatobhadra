package com.sarvatobhadra.backend.common.enums;

/**
 * Enumeration of Indicator of Compromise (IOC) types extracted by the AI/NLP processing layer.
 * Encompasses technical artifacts (IP, Domain, Hash) and threat context entities (Malware, Actor, Target).
 */
public enum IndicatorType {
    IP,
    DOMAIN,
    URL,
    FILE_HASH,
    MALWARE,
    THREAT_ACTOR,
    ORGANIZATION,
    LOCATION,
    TIMESTAMP,
    TARGET,
    ATTACK_TYPE
}
