-- =============================================================================
-- Flyway Seed Data Script (V2__seed_initial_data.sql)
-- Inserts initial demo accounts, sample SIEM alerts, sensor events, threat clusters,
-- BLUF report, and analyst feedback.
-- =============================================================================

-- 1. Insert Initial System Users (Passwords: 'password123' BCrypt hashed)
INSERT INTO users (username, password, email, role, enabled) VALUES
('admin', '$2a$10$8.UnVuG9HHgffUDAlk8qfOuVGkqRzgVymY0n9p.gBwzS/QJd/e1Xm', 'admin@sarvatobhadra.com', 'ROLE_ADMIN', TRUE),
('analyst1', '$2a$10$8.UnVuG9HHgffUDAlk8qfOuVGkqRzgVymY0n9p.gBwzS/QJd/e1Xm', 'analyst1@sarvatobhadra.com', 'ROLE_ANALYST', TRUE);

-- 2. Insert Sample Correlated Threat Cluster
INSERT INTO threat_clusters (title, description, correlation_score, threat_score, priority, status, affected_target, primary_actor, alert_count, report_count) VALUES
('Potential Coordinated Cyber Activity targeting Defense Infrastructure', 'Multiple independent sources (SIEM, Sensor, OSINT, Intel Report) indicate malicious communication and command execution originating from IP 192.168.1.100.', 85.0, 92, 'CRITICAL', 'OPEN', 'Defence Infrastructure / Server ABC', 'APT29 / Cozy Bear', 4, 1);

-- 3. Insert Sample Ingested Alerts linked to Cluster 1
INSERT INTO alerts (source, timestamp, severity, event_type, description, raw_payload, cluster_id, target, threat_actor) VALUES
('SIEM', CURRENT_TIMESTAMP, 'CRITICAL', 'NETWORK_ACTIVITY', 'Suspicious outbound connection detected from IP 192.168.1.100 targeting server ABC', '{"source":"SIEM","severity":"CRITICAL","eventType":"NETWORK_ACTIVITY","indicators":[{"type":"IP","value":"192.168.1.100"}]}', 1, 'Defence infrastructure', 'APT29'),
('SENSOR', CURRENT_TIMESTAMP, 'HIGH', 'MALWARE_EXECUTION', 'Cyber sensor detected unauthorized Cobalt Strike Beacon process execution from IP 192.168.1.100', '{"source":"SENSOR","severity":"HIGH","eventType":"MALWARE_EXECUTION"}', 1, 'Defence infrastructure', 'APT29'),
('OSINT', CURRENT_TIMESTAMP, 'HIGH', 'EXFILTRATION_FEED', 'OSINT feed reports IP 192.168.1.100 actively involved in credential scraping targeting defense sector', '{"source":"OSINT","severity":"HIGH"}', 1, 'Defence infrastructure', 'APT29'),
('SIEM', CURRENT_TIMESTAMP, 'MEDIUM', 'ANOMALOUS_LOGIN', 'Anomalous admin login attempt from internal segment targeting server ABC', '{"source":"SIEM","severity":"MEDIUM"}', 1, 'Defence infrastructure', 'APT29');

-- 4. Insert Sample Intelligence Report linked to Cluster 1
INSERT INTO intelligence_reports (title, source, content, summary, file_type, file_path, cluster_id) VALUES
('Threat Briefing: APT29 Infrastructure Expansion', 'INTEL_REPORT', 'Intelligence analysis indicates APT29 has established malicious proxy nodes including IP 192.168.1.100. Target includes defence infrastructure.', 'APT29 infrastructure expansion brief identifying IP 192.168.1.100', 'PDF', 'APT29_Briefing.pdf', 1);

-- 5. Insert Sample Indicators
INSERT INTO indicators (type, indicator_value, alert_id, report_id, confidence) VALUES
('IP', '192.168.1.100', 1, NULL, 0.98),
('TARGET', 'Defence Infrastructure', 1, NULL, 0.90),
('THREAT_ACTOR', 'APT29', 1, NULL, 0.95),
('MALWARE', 'Cobalt Strike Beacon', 2, NULL, 0.92),
('IP', '192.168.1.100', NULL, 1, 0.99);

-- 6. Insert Sample BLUF Report for Cluster 1
INSERT INTO bluf_reports (cluster_id, threat_summary, confidence, affected_target, evidence_summary, assessment, priority, analyst_review_status) VALUES
(1, 'Potential coordinated cyber activity.', 'HIGH', 'Defence infrastructure.', '• 2 SIEM alerts\n• 1 cyber sensor event\n• 1 OSINT report\n• 1 intelligence report', 'Multiple independent sources indicate potential coordinated activity targeting defence infrastructure.', 'CRITICAL', 'REQUIRED');
