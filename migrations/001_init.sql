CREATE TYPE severity_level AS ENUM ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL');
CREATE TYPE environment_type AS ENUM ('production', 'staging', 'development');

CREATE TABLE IF NOT EXISTS projects (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(255) NOT NULL UNIQUE,
    owner       VARCHAR(255),
    environment environment_type NOT NULL DEFAULT 'development',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scans (
    id           SERIAL PRIMARY KEY,
    project_id   INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    image_name   VARCHAR(512) NOT NULL,
    image_digest VARCHAR(255),
    scanned_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    raw_json     JSONB
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id                 SERIAL PRIMARY KEY,
    scan_id            INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    cve_id             VARCHAR(50) NOT NULL,
    severity           severity_level NOT NULL,
    package_name       VARCHAR(255) NOT NULL,
    installed_version  VARCHAR(255),
    fixed_version      VARCHAR(255),
    title              TEXT,
    is_fixed           BOOLEAN NOT NULL DEFAULT FALSE,
    first_seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vulnerabilities_scan_id   ON vulnerabilities(scan_id);
CREATE INDEX idx_vulnerabilities_severity  ON vulnerabilities(severity);
CREATE INDEX idx_vulnerabilities_cve_id    ON vulnerabilities(cve_id);
CREATE INDEX idx_scans_project_id          ON scans(project_id);
CREATE INDEX idx_scans_scanned_at          ON scans(scanned_at DESC);
