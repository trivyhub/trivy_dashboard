package models

import "time"

// ── Auth ──────────────────────────────────────────────────────────────────────

type Organization struct {
	ID        int       `json:"id" db:"id"`
	Name      string    `json:"name" db:"name"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
	RoleViewer = "viewer"
)

type User struct {
	ID             int       `json:"id" db:"id"`
	OrganizationID int       `json:"organization_id" db:"organization_id"`
	Email          string    `json:"email" db:"email"`
	PasswordHash   string    `json:"-" db:"password_hash"`
	Role           string    `json:"role" db:"role"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
}

type RegisterRequest struct {
	OrgName  string `json:"org_name" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

type InviteRequest struct {
	Email string `json:"email" binding:"required,email"`
	Role  string `json:"role" binding:"required,oneof=admin member viewer"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type AuthResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

// ── Trivy JSON ────────────────────────────────────────────────────────────────

type TrivyReport struct {
	SchemaVersion int      `json:"SchemaVersion"`
	ArtifactName  string   `json:"ArtifactName"`
	ArtifactType  string   `json:"ArtifactType"`
	Metadata      *Metadata `json:"Metadata,omitempty"`
	Results       []Result  `json:"Results"`
}

type Metadata struct {
	ImageID     string   `json:"ImageID,omitempty"`
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
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion,omitempty"`
	Title            string `json:"Title,omitempty"`
	Severity         string `json:"Severity"`
}

// ── Ingestion ─────────────────────────────────────────────────────────────────

type IngestRequest struct {
	ProjectName string      `json:"project_name" binding:"required"`
	Environment string      `json:"environment"`
	Owner       string      `json:"owner"`
	PipelineID  string      `json:"pipeline_id"`
	PipelineURL string      `json:"pipeline_url"`
	Report      TrivyReport `json:"report" binding:"required"`
}

// ── DB ────────────────────────────────────────────────────────────────────────

type Project struct {
	ID             int       `json:"id" db:"id"`
	OrganizationID int       `json:"organization_id" db:"organization_id"`
	Name           string    `json:"name" db:"name"`
	Environment    string    `json:"environment" db:"environment"`
	Owner          string    `json:"owner" db:"owner"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
}

type Scan struct {
	ID          int        `json:"id" db:"id"`
	ProjectID   int        `json:"project_id" db:"project_id"`
	ImageName   string     `json:"image_name" db:"image_name"`
	ImageDigest string     `json:"image_digest" db:"image_digest"`
	ScannedAt   time.Time  `json:"scanned_at" db:"scanned_at"`
	PipelineID  *string    `json:"pipeline_id" db:"pipeline_id"`
	PipelineURL *string    `json:"pipeline_url" db:"pipeline_url"`
}

type ScanSummary struct {
	Scan
	Critical int `json:"critical" db:"critical"`
	High     int `json:"high" db:"high"`
	Medium   int `json:"medium" db:"medium"`
	Low      int `json:"low" db:"low"`
	Total    int `json:"total" db:"total"`
}

type DBVulnerability struct {
	ID               int       `json:"id" db:"id"`
	ScanID           int       `json:"scan_id" db:"scan_id"`
	CVEID            string    `json:"cve_id" db:"cve_id"`
	Severity         string    `json:"severity" db:"severity"`
	PackageName      string    `json:"package_name" db:"package_name"`
	InstalledVersion string    `json:"installed_version" db:"installed_version"`
	FixedVersion     string    `json:"fixed_version" db:"fixed_version"`
	Title            string    `json:"title" db:"title"`
	IsFixed          bool      `json:"is_fixed" db:"is_fixed"`
	FirstSeenAt      time.Time `json:"first_seen_at" db:"first_seen_at"`
}

type ProjectSummary struct {
	Project
	LastScan   *time.Time `json:"last_scan" db:"last_scan"`
	TotalScans int        `json:"total_scans" db:"total_scans"`
	Critical   int        `json:"critical" db:"critical"`
	High       int        `json:"high" db:"high"`
	Medium     int        `json:"medium" db:"medium"`
	Low        int        `json:"low" db:"low"`
}

type APIKey struct {
	ID             int        `json:"id" db:"id"`
	OrganizationID int        `json:"organization_id" db:"organization_id"`
	Name           string     `json:"name" db:"name"`
	KeyPrefix      string     `json:"key_prefix" db:"key_prefix"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at" db:"last_used_at"`
	Revoked        bool       `json:"revoked" db:"revoked"`
}

type CreateAPIKeyRequest struct {
	Name string `json:"name" binding:"required"`
}

type CreateAPIKeyResponse struct {
	APIKey
	Key string `json:"key"`
}

type DiffResult struct {
	NewVulnerabilities      []DBVulnerability `json:"new_vulnerabilities"`
	ResolvedVulnerabilities []DBVulnerability `json:"resolved_vulnerabilities"`
	PreviousScanID          int               `json:"previous_scan_id"`
	CurrentScanID           int               `json:"current_scan_id"`
}
