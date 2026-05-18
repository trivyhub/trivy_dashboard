package repository

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/theomorin/trivy-dashboard/internal/models"
)

type Repository struct {
	db *pgxpool.Pool
}

func New(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

// ── Auth ──────────────────────────────────────────────────────────────────────

func (r *Repository) CreateOrganization(ctx context.Context, name string) (*models.Organization, error) {
	org := &models.Organization{}
	err := r.db.QueryRow(ctx, `
		INSERT INTO organizations (name) VALUES ($1)
		RETURNING id, name, created_at
	`, name).Scan(&org.ID, &org.Name, &org.CreatedAt)
	return org, err
}

func (r *Repository) CreateUser(ctx context.Context, orgID int, email, passwordHash, role string) (*models.User, error) {
	u := &models.User{}
	err := r.db.QueryRow(ctx, `
		INSERT INTO users (organization_id, email, password_hash, role)
		VALUES ($1, $2, $3, $4)
		RETURNING id, organization_id, email, role, created_at
	`, orgID, email, passwordHash, role).Scan(&u.ID, &u.OrganizationID, &u.Email, &u.Role, &u.CreatedAt)
	return u, err
}

func (r *Repository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	u := &models.User{}
	err := r.db.QueryRow(ctx, `
		SELECT id, organization_id, email, password_hash, role, created_at
		FROM users WHERE email = $1
	`, email).Scan(&u.ID, &u.OrganizationID, &u.Email, &u.PasswordHash, &u.Role, &u.CreatedAt)
	return u, err
}

func (r *Repository) ListMembers(ctx context.Context, orgID int) ([]models.User, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, organization_id, email, role, created_at
		FROM users WHERE organization_id = $1 ORDER BY created_at
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []models.User
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.OrganizationID, &u.Email, &u.Role, &u.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (r *Repository) UpdatePassword(ctx context.Context, userID int, hash string) error {
	_, err := r.db.Exec(ctx, `UPDATE users SET password_hash = $1 WHERE id = $2`, hash, userID)
	return err
}

func (r *Repository) UpdateUserRole(ctx context.Context, orgID, userID int, role string) error {
	_, err := r.db.Exec(ctx, `
		UPDATE users SET role = $1 WHERE id = $2 AND organization_id = $3
	`, role, userID, orgID)
	return err
}

func (r *Repository) RemoveMember(ctx context.Context, orgID, userID int) error {
	_, err := r.db.Exec(ctx, `
		DELETE FROM users WHERE id = $1 AND organization_id = $2 AND role != 'owner'
	`, userID, orgID)
	return err
}

// ── API Keys ──────────────────────────────────────────────────────────────────

func (r *Repository) CreateAPIKey(ctx context.Context, orgID int, name, keyHash, keyPrefix string) (*models.APIKey, error) {
	k := &models.APIKey{}
	err := r.db.QueryRow(ctx, `
		INSERT INTO api_keys (organization_id, name, key_hash, key_prefix)
		VALUES ($1, $2, $3, $4)
		RETURNING id, organization_id, name, key_prefix, created_at, last_used_at, revoked
	`, orgID, name, keyHash, keyPrefix).Scan(
		&k.ID, &k.OrganizationID, &k.Name, &k.KeyPrefix,
		&k.CreatedAt, &k.LastUsedAt, &k.Revoked,
	)
	return k, err
}

func (r *Repository) GetAPIKeyByHash(ctx context.Context, keyHash string) (*models.APIKey, error) {
	k := &models.APIKey{}
	err := r.db.QueryRow(ctx, `
		SELECT id, organization_id, name, key_prefix, created_at, last_used_at, revoked
		FROM api_keys WHERE key_hash = $1 AND revoked = false
	`, keyHash).Scan(
		&k.ID, &k.OrganizationID, &k.Name, &k.KeyPrefix,
		&k.CreatedAt, &k.LastUsedAt, &k.Revoked,
	)
	return k, err
}

func (r *Repository) ListAPIKeys(ctx context.Context, orgID int) ([]models.APIKey, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, organization_id, name, key_prefix, created_at, last_used_at, revoked
		FROM api_keys WHERE organization_id = $1
		ORDER BY created_at DESC
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []models.APIKey
	for rows.Next() {
		var k models.APIKey
		if err := rows.Scan(&k.ID, &k.OrganizationID, &k.Name, &k.KeyPrefix,
			&k.CreatedAt, &k.LastUsedAt, &k.Revoked); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func (r *Repository) RevokeAPIKey(ctx context.Context, orgID, keyID int) error {
	_, err := r.db.Exec(ctx, `
		UPDATE api_keys SET revoked = true
		WHERE id = $1 AND organization_id = $2
	`, keyID, orgID)
	return err
}

func (r *Repository) TouchAPIKey(ctx context.Context, keyID int) {
	r.db.Exec(ctx, `UPDATE api_keys SET last_used_at = NOW() WHERE id = $1`, keyID)
}

// ── Projects ──────────────────────────────────────────────────────────────────

func (r *Repository) UpsertProject(ctx context.Context, orgID int, name, owner, env string) (*models.Project, error) {
	if env == "" {
		env = "production"
	}
	p := &models.Project{}
	err := r.db.QueryRow(ctx, `
		INSERT INTO projects (organization_id, name, owner, environment)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (organization_id, name) DO UPDATE
			SET owner = EXCLUDED.owner,
			    environment = EXCLUDED.environment
		RETURNING id, organization_id, name, owner, environment, created_at
	`, orgID, name, owner, env).Scan(&p.ID, &p.OrganizationID, &p.Name, &p.Owner, &p.Environment, &p.CreatedAt)
	return p, err
}

func (r *Repository) GetProjectByName(ctx context.Context, orgID int, name string) (*models.Project, error) {
	p := &models.Project{}
	err := r.db.QueryRow(ctx, `
		SELECT id, organization_id, name, owner, environment, created_at
		FROM projects WHERE organization_id = $1 AND name = $2
	`, orgID, name).Scan(&p.ID, &p.OrganizationID, &p.Name, &p.Owner, &p.Environment, &p.CreatedAt)
	return p, err
}

func (r *Repository) ListProjects(ctx context.Context, orgID int) ([]models.ProjectSummary, error) {
	rows, err := r.db.Query(ctx, `
		SELECT
			p.id, p.organization_id, p.name, p.owner, p.environment, p.created_at,
			MAX(s.scanned_at) AS last_scan,
			COUNT(DISTINCT s.id) AS total_scans,
			COUNT(CASE WHEN v.severity = 'CRITICAL' THEN 1 END) AS critical,
			COUNT(CASE WHEN v.severity = 'HIGH'     THEN 1 END) AS high,
			COUNT(CASE WHEN v.severity = 'MEDIUM'   THEN 1 END) AS medium,
			COUNT(CASE WHEN v.severity = 'LOW'      THEN 1 END) AS low
		FROM projects p
		LEFT JOIN scans s ON s.project_id = p.id
		LEFT JOIN vulnerabilities v ON v.scan_id = (
			SELECT id FROM scans WHERE project_id = p.id ORDER BY scanned_at DESC LIMIT 1
		)
		WHERE p.organization_id = $1
		GROUP BY p.id
		ORDER BY p.name
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var summaries []models.ProjectSummary
	for rows.Next() {
		var ps models.ProjectSummary
		err := rows.Scan(
			&ps.ID, &ps.OrganizationID, &ps.Name, &ps.Owner, &ps.Environment, &ps.CreatedAt,
			&ps.LastScan, &ps.TotalScans,
			&ps.Critical, &ps.High, &ps.Medium, &ps.Low,
		)
		if err != nil {
			return nil, err
		}
		summaries = append(summaries, ps)
	}
	return summaries, rows.Err()
}

// ── Scans ─────────────────────────────────────────────────────────────────────

func (r *Repository) CreateScan(ctx context.Context, projectID int, imageName, digest, pipelineID, pipelineURL string, raw json.RawMessage, langs []string) (*models.Scan, error) {
	s := &models.Scan{}
	var pid, purl *string
	if pipelineID != "" {
		pid = &pipelineID
	}
	if pipelineURL != "" {
		purl = &pipelineURL
	}
	if langs == nil {
		langs = []string{}
	}
	err := r.db.QueryRow(ctx, `
		INSERT INTO scans (project_id, image_name, image_digest, pipeline_id, pipeline_url, raw_json, langs)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, project_id, image_name, image_digest, scanned_at, pipeline_id, pipeline_url, langs
	`, projectID, imageName, digest, pid, purl, raw, langs).Scan(
		&s.ID, &s.ProjectID, &s.ImageName, &s.ImageDigest, &s.ScannedAt, &s.PipelineID, &s.PipelineURL, &s.Langs,
	)
	return s, err
}

func (r *Repository) ListScans(ctx context.Context, projectID int) ([]models.ScanSummary, error) {
	rows, err := r.db.Query(ctx, `
		SELECT
			s.id, s.project_id, s.image_name, s.image_digest, s.scanned_at,
			s.pipeline_id, s.pipeline_url, s.langs,
			COUNT(CASE WHEN v.severity = 'CRITICAL' THEN 1 END) AS critical,
			COUNT(CASE WHEN v.severity = 'HIGH'     THEN 1 END) AS high,
			COUNT(CASE WHEN v.severity = 'MEDIUM'   THEN 1 END) AS medium,
			COUNT(CASE WHEN v.severity = 'LOW'      THEN 1 END) AS low,
			COUNT(v.id) AS total
		FROM scans s
		LEFT JOIN vulnerabilities v ON v.scan_id = s.id
		WHERE s.project_id = $1
		GROUP BY s.id
		ORDER BY s.scanned_at DESC
	`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []models.ScanSummary
	for rows.Next() {
		var ss models.ScanSummary
		if err := rows.Scan(
			&ss.ID, &ss.ProjectID, &ss.ImageName, &ss.ImageDigest, &ss.ScannedAt,
			&ss.PipelineID, &ss.PipelineURL, &ss.Langs,
			&ss.Critical, &ss.High, &ss.Medium, &ss.Low, &ss.Total,
		); err != nil {
			return nil, err
		}
		scans = append(scans, ss)
	}
	return scans, rows.Err()
}

func (r *Repository) GetLastTwoScans(ctx context.Context, projectID int) ([]models.Scan, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, project_id, image_name, image_digest, scanned_at, pipeline_id, pipeline_url
		FROM scans WHERE project_id = $1
		ORDER BY scanned_at DESC LIMIT 2
	`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []models.Scan
	for rows.Next() {
		var s models.Scan
		if err := rows.Scan(&s.ID, &s.ProjectID, &s.ImageName, &s.ImageDigest, &s.ScannedAt, &s.PipelineID, &s.PipelineURL); err != nil {
			return nil, err
		}
		scans = append(scans, s)
	}
	return scans, rows.Err()
}

// ── Vulnerabilities ───────────────────────────────────────────────────────────

func (r *Repository) BulkInsertVulnerabilities(ctx context.Context, scanID int, vulns []models.DBVulnerability) error {
	if len(vulns) == 0 {
		return nil
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	for _, v := range vulns {
		_, err := tx.Exec(ctx, `
			INSERT INTO vulnerabilities
				(scan_id, cve_id, severity, package_name, installed_version, fixed_version, title, description, primary_url, is_fixed, cvss_score)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		`, scanID, v.CVEID, v.Severity, v.PackageName, v.InstalledVersion, v.FixedVersion, v.Title, v.Description, v.PrimaryURL, v.IsFixed, v.CVSSScore)
		if err != nil {
			return fmt.Errorf("insert vulnerability %s: %w", v.CVEID, err)
		}
	}
	return tx.Commit(ctx)
}

func (r *Repository) GetVulnerabilitiesByScan(ctx context.Context, scanID int) ([]models.DBVulnerability, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, scan_id, cve_id, severity, package_name,
		       installed_version, fixed_version, title, description, primary_url, is_fixed, first_seen_at, cvss_score
		FROM vulnerabilities WHERE scan_id = $1
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulns []models.DBVulnerability
	for rows.Next() {
		var v models.DBVulnerability
		if err := rows.Scan(
			&v.ID, &v.ScanID, &v.CVEID, &v.Severity, &v.PackageName,
			&v.InstalledVersion, &v.FixedVersion, &v.Title, &v.Description, &v.PrimaryURL, &v.IsFixed, &v.FirstSeenAt, &v.CVSSScore,
		); err != nil {
			return nil, err
		}
		vulns = append(vulns, v)
	}
	return vulns, rows.Err()
}

func (r *Repository) GetLatestVulnerabilitiesByOrg(ctx context.Context, orgID int, severity, projectName string, limit, offset int) ([]models.DBVulnerability, int, error) {
	args := []any{orgID}
	filters := ""
	if severity != "" {
		args = append(args, severity)
		filters += fmt.Sprintf(" AND v.severity = $%d", len(args))
	}
	if projectName != "" {
		args = append(args, projectName)
		filters += fmt.Sprintf(" AND p.name = $%d", len(args))
	}

	// total
	var total int
	countSQL := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM vulnerabilities v
		JOIN scans s ON s.id = v.scan_id
		JOIN projects p ON p.id = s.project_id
		WHERE p.organization_id = $1
		  AND s.id = (SELECT id FROM scans WHERE project_id = p.id ORDER BY scanned_at DESC LIMIT 1)
		%s
	`, filters)
	r.db.QueryRow(ctx, countSQL, args...).Scan(&total)

	// pagination args
	args = append(args, limit, offset)
	dataSQL := fmt.Sprintf(`
		SELECT v.id, v.scan_id, v.cve_id, v.severity, v.package_name,
		       v.installed_version, v.fixed_version, v.title, v.description, v.primary_url, v.is_fixed, v.first_seen_at, v.cvss_score
		FROM vulnerabilities v
		JOIN scans s ON s.id = v.scan_id
		JOIN projects p ON p.id = s.project_id
		WHERE p.organization_id = $1
		  AND s.id = (SELECT id FROM scans WHERE project_id = p.id ORDER BY scanned_at DESC LIMIT 1)
		%s
		ORDER BY CASE v.severity
			WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
			WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'  THEN 4 ELSE 5
		END, p.name, v.cve_id
		LIMIT $%d OFFSET $%d
	`, filters, len(args)-1, len(args))

	rows, err := r.db.Query(ctx, dataSQL, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var vulns []models.DBVulnerability
	for rows.Next() {
		var v models.DBVulnerability
		if err := rows.Scan(
			&v.ID, &v.ScanID, &v.CVEID, &v.Severity, &v.PackageName,
			&v.InstalledVersion, &v.FixedVersion, &v.Title, &v.Description, &v.PrimaryURL, &v.IsFixed, &v.FirstSeenAt, &v.CVSSScore,
		); err != nil {
			return nil, 0, err
		}
		vulns = append(vulns, v)
	}
	return vulns, total, rows.Err()
}
