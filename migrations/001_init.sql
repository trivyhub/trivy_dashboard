CREATE TABLE IF NOT EXISTS organizations (
    id         SERIAL PRIMARY KEY,
    name       VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email           VARCHAR(255) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS projects (
    id              SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    environment     VARCHAR(50) NOT NULL DEFAULT 'production',
    owner           VARCHAR(255),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(organization_id, name)
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
    id                SERIAL PRIMARY KEY,
    scan_id           INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    cve_id            VARCHAR(50) NOT NULL,
    severity          VARCHAR(20) NOT NULL,
    package_name      VARCHAR(255) NOT NULL,
    installed_version VARCHAR(255),
    fixed_version     VARCHAR(255),
    title             TEXT,
    is_fixed          BOOLEAN NOT NULL DEFAULT FALSE,
    first_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_organization_id        ON users(organization_id);
CREATE INDEX idx_projects_organization_id     ON projects(organization_id);
CREATE INDEX idx_scans_project_id             ON scans(project_id);
CREATE INDEX idx_scans_scanned_at             ON scans(scanned_at DESC);
CREATE INDEX idx_vulnerabilities_scan_id      ON vulnerabilities(scan_id);
CREATE INDEX idx_vulnerabilities_severity     ON vulnerabilities(severity);
