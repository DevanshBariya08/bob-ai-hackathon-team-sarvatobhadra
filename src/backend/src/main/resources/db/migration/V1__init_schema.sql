-- =============================================================================
-- Flyway Database Migration Schema Script (V1__init_schema.sql)
-- Target Platform: PostgreSQL / H2 Database
-- Project: Threat Intelligence Correlation Platform
-- =============================================================================

-- 1. Create Users Table (Authentication & RBAC)
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role VARCHAR(20) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 2. Create Threat Clusters Table (Correlated Incidents)
CREATE TABLE IF NOT EXISTS threat_clusters (
    id BIGSERIAL PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    correlation_score DOUBLE PRECISION,
    threat_score INT,
    priority VARCHAR(20) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'OPEN',
    affected_target VARCHAR(200),
    primary_actor VARCHAR(100),
    alert_count INT DEFAULT 0,
    report_count INT DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 3. Create Alerts Table (SIEM, Sensor Events, OSINT Ingestion)
CREATE TABLE IF NOT EXISTS alerts (
    id BIGSERIAL PRIMARY KEY,
    source VARCHAR(20) NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    severity VARCHAR(20) NOT NULL,
    event_type VARCHAR(100),
    description TEXT,
    raw_payload TEXT,
    cluster_id BIGINT,
    target VARCHAR(150),
    threat_actor VARCHAR(100),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_alert_cluster FOREIGN KEY (cluster_id) REFERENCES threat_clusters(id) ON DELETE SET NULL
);

-- 4. Create Intelligence Reports Table (PDF, DOCX, TXT Documents)
CREATE TABLE IF NOT EXISTS intelligence_reports (
    id BIGSERIAL PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    source VARCHAR(20) NOT NULL DEFAULT 'INTEL_REPORT',
    content TEXT NOT NULL,
    summary TEXT,
    file_type VARCHAR(20),
    file_path VARCHAR(300),
    cluster_id BIGINT,
    uploaded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_report_cluster FOREIGN KEY (cluster_id) REFERENCES threat_clusters(id) ON DELETE SET NULL
);

-- 5. Create Indicators Table (IOCs: IP, Domain, Hash, Malware, Actor, Target)
CREATE TABLE IF NOT EXISTS indicators (
    id BIGSERIAL PRIMARY KEY,
    type VARCHAR(30) NOT NULL,
    indicator_value VARCHAR(255) NOT NULL,
    alert_id BIGINT,
    report_id BIGINT,
    confidence DOUBLE PRECISION DEFAULT 0.90,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_indicator_alert FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE,
    CONSTRAINT fk_indicator_report FOREIGN KEY (report_id) REFERENCES intelligence_reports(id) ON DELETE CASCADE
);

CREATE INDEX idx_indicator_val_type ON indicators (indicator_value, type);

-- 6. Create BLUF Reports Table (Bottom Line Up Front Assessments)
CREATE TABLE IF NOT EXISTS bluf_reports (
    id BIGSERIAL PRIMARY KEY,
    cluster_id BIGINT NOT NULL,
    threat_summary VARCHAR(300) NOT NULL,
    confidence VARCHAR(20) DEFAULT 'HIGH',
    affected_target VARCHAR(200),
    evidence_summary TEXT,
    assessment TEXT,
    priority VARCHAR(20) NOT NULL,
    analyst_review_status VARCHAR(30) DEFAULT 'REQUIRED',
    generated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_bluf_cluster FOREIGN KEY (cluster_id) REFERENCES threat_clusters(id) ON DELETE CASCADE
);

-- 7. Create Analyst Feedback Table (Human-in-the-Loop Reviews)
CREATE TABLE IF NOT EXISTS analyst_feedback (
    id BIGSERIAL PRIMARY KEY,
    cluster_id BIGINT NOT NULL,
    bluf_id BIGINT,
    analyst_username VARCHAR(50) NOT NULL,
    action VARCHAR(20) NOT NULL,
    modified_priority VARCHAR(20),
    comments TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_feedback_cluster FOREIGN KEY (cluster_id) REFERENCES threat_clusters(id) ON DELETE CASCADE
);
