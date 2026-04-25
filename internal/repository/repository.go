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

// UpsertProject crée ou retourne un projet existant
func (r *Repository) UpsertProject(ctx context.Context, name, owner, env string) (*models.Project, error) {
	if env == "" {
		env = "development"
	}
	p := &models.Project{}
	err := r.db.QueryRow(ctx, `
		INSERT INTO projects (name, owner, environment)
		VALUES ($1, $2, $3)
		ON CONFLICT (name) DO UPDATE
			SET owner = EXCLUDED.owner,
			    environment = EXCLUDED.environment
		RETURNING id, name, owner, environment, created_at
	`, name, owner, env).Scan(&p.ID, &p.Name, &p.Owner, &p.Environment, &p.CreatedAt)
	return p, err
}

// CreateScan insère un nouveau scan
func (r *Repository) CreateScan(ctx context.Context, projectID int, imageName, digest string, raw json.RawMessage) (*models.Scan, error) {
	s := &models.Scan{}
	err := r.db.QueryRow(ctx, `
		INSERT INTO scans (project_id, image_name, image_digest, raw_json)
		VALUES ($1, $2, $3, $4)
		RETURNING id, project_id, image_name, image_digest, scanned_at
	`, projectID, imageName, digest, raw).Scan(&s.ID, &s.ProjectID, &s.ImageName, &s.ImageDigest, &s.ScannedAt)
	return s, err
}

// BulkInsertVulnerabilities insère toutes les CVE d'un scan
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
				(scan_id, cve_id, severity, package_name, installed_version, fixed_version, title, is_fixed)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		`, scanID, v.CVEID, v.Severity, v.PackageName, v.InstalledVersion, v.FixedVersion, v.Title, v.IsFixed)
		if err != nil {
			return fmt.Errorf("insert vulnerability %s: %w", v.CVEID, err)
		}
	}
	return tx.Commit(ctx)
}

// ListProjects retourne le résumé de tous les projets
func (r *Repository) ListProjects(ctx context.Context) ([]models.ProjectSummary, error) {
	rows, err := r.db.Query(ctx, `
		SELECT
			p.id, p.name, p.owner, p.environment, p.created_at,
			MAX(s.scanned_at) AS last_scan,
			COUNT(DISTINCT s.id) AS total_scans,
			COUNT(CASE WHEN v.severity = 'CRITICAL' THEN 1 END) AS critical,
			COUNT(CASE WHEN v.severity = 'HIGH'     THEN 1 END) AS high,
			COUNT(CASE WHEN v.severity = 'MEDIUM'   THEN 1 END) AS medium,
			COUNT(CASE WHEN v.severity = 'LOW'      THEN 1 END) AS low,
			COUNT(CASE WHEN v.severity = 'UNKNOWN'  THEN 1 END) AS unknown
		FROM projects p
		LEFT JOIN scans s ON s.project_id = p.id
		LEFT JOIN vulnerabilities v ON v.scan_id = (
			SELECT id FROM scans
			WHERE project_id = p.id
			ORDER BY scanned_at DESC
			LIMIT 1
		)
		GROUP BY p.id
		ORDER BY p.name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var summaries []models.ProjectSummary
	for rows.Next() {
		var ps models.ProjectSummary
		err := rows.Scan(
			&ps.ID, &ps.Name, &ps.Owner, &ps.Environment, &ps.CreatedAt,
			&ps.LastScan, &ps.TotalScans,
			&ps.SeveritySummary.Critical, &ps.SeveritySummary.High,
			&ps.SeveritySummary.Medium, &ps.SeveritySummary.Low, &ps.SeveritySummary.Unknown,
		)
		if err != nil {
			return nil, err
		}
		summaries = append(summaries, ps)
	}
	return summaries, rows.Err()
}

// GetProjectByName retourne un projet par son nom
func (r *Repository) GetProjectByName(ctx context.Context, name string) (*models.Project, error) {
	p := &models.Project{}
	err := r.db.QueryRow(ctx, `
		SELECT id, name, owner, environment, created_at
		FROM projects WHERE name = $1
	`, name).Scan(&p.ID, &p.Name, &p.Owner, &p.Environment, &p.CreatedAt)
	return p, err
}

// GetLastTwoScans retourne les deux derniers scans d'un projet
func (r *Repository) GetLastTwoScans(ctx context.Context, projectID int) ([]models.Scan, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, project_id, image_name, image_digest, scanned_at
		FROM scans
		WHERE project_id = $1
		ORDER BY scanned_at DESC
		LIMIT 2
	`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []models.Scan
	for rows.Next() {
		var s models.Scan
		if err := rows.Scan(&s.ID, &s.ProjectID, &s.ImageName, &s.ImageDigest, &s.ScannedAt); err != nil {
			return nil, err
		}
		scans = append(scans, s)
	}
	return scans, rows.Err()
}

// GetVulnerabilitiesByScan retourne toutes les CVE d'un scan
func (r *Repository) GetVulnerabilitiesByScan(ctx context.Context, scanID int) ([]models.DBVulnerability, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, scan_id, cve_id, severity, package_name,
		       installed_version, fixed_version, title, is_fixed, first_seen_at
		FROM vulnerabilities
		WHERE scan_id = $1
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
			&v.InstalledVersion, &v.FixedVersion, &v.Title, &v.IsFixed, &v.FirstSeenAt,
		); err != nil {
			return nil, err
		}
		vulns = append(vulns, v)
	}
	return vulns, rows.Err()
}
