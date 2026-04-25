package models

import "time"

// TrivyReport représente la structure racine d'un rapport JSON Trivy
type TrivyReport struct {
	SchemaVersion int           `json:"SchemaVersion"`
	ArtifactName  string        `json:"ArtifactName"`
	ArtifactType  string        `json:"ArtifactType"`
	Metadata      *Metadata     `json:"Metadata,omitempty"`
	Results       []Result      `json:"Results"`
}

type Metadata struct {
	ImageID     string   `json:"ImageID,omitempty"`
	DiffIDs     []string `json:"DiffIDs,omitempty"`
	RepoTags    []string `json:"RepoTags,omitempty"`
	RepoDigests []string `json:"RepoDigests,omitempty"`
}

type Result struct {
	Target          string          `json:"Target"`
	Class           string          `json:"Class"`
	Type            string          `json:"Type"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities,omitempty"`
}

type Vulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion,omitempty"`
	Title            string   `json:"Title,omitempty"`
	Description      string   `json:"Description,omitempty"`
	Severity         string   `json:"Severity"`
	References       []string `json:"References,omitempty"`
}

// IngestRequest est le body attendu sur POST /api/v1/report
type IngestRequest struct {
	ProjectName string      `json:"project_name" binding:"required"`
	Environment string      `json:"environment"`
	Owner       string      `json:"owner"`
	Report      TrivyReport `json:"report" binding:"required"`
}

// DB models

type Project struct {
	ID          int       `db:"id"`
	Name        string    `db:"name"`
	Owner       string    `db:"owner"`
	Environment string    `db:"environment"`
	CreatedAt   time.Time `db:"created_at"`
}

type Scan struct {
	ID          int       `db:"id"`
	ProjectID   int       `db:"project_id"`
	ImageName   string    `db:"image_name"`
	ImageDigest string    `db:"image_digest"`
	ScannedAt   time.Time `db:"scanned_at"`
}

type DBVulnerability struct {
	ID               int       `db:"id"`
	ScanID           int       `db:"scan_id"`
	CVEID            string    `db:"cve_id"`
	Severity         string    `db:"severity"`
	PackageName      string    `db:"package_name"`
	InstalledVersion string    `db:"installed_version"`
	FixedVersion     string    `db:"fixed_version"`
	Title            string    `db:"title"`
	IsFixed          bool      `db:"is_fixed"`
	FirstSeenAt      time.Time `db:"first_seen_at"`
}

// SeveritySummary est utilisé pour les réponses agrégées
type SeveritySummary struct {
	Critical int `json:"critical" db:"critical"`
	High     int `json:"high" db:"high"`
	Medium   int `json:"medium" db:"medium"`
	Low      int `json:"low" db:"low"`
	Unknown  int `json:"unknown" db:"unknown"`
}

type ProjectSummary struct {
	Project
	LastScan        *time.Time      `json:"last_scan" db:"last_scan"`
	TotalScans      int             `json:"total_scans" db:"total_scans"`
	SeveritySummary SeveritySummary `json:"severity_summary"`
}

type DiffResult struct {
	NewVulnerabilities     []DBVulnerability `json:"new_vulnerabilities"`
	ResolvedVulnerabilities []DBVulnerability `json:"resolved_vulnerabilities"`
	PreviousScanID         int               `json:"previous_scan_id"`
	CurrentScanID          int               `json:"current_scan_id"`
}
