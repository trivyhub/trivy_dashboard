package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/theomorin/trivy-dashboard/internal/models"
	"github.com/theomorin/trivy-dashboard/internal/repository"
)

type Handler struct {
	repo *repository.Repository
}

func New(repo *repository.Repository) *Handler {
	return &Handler{repo: repo}
}

// POST /api/v1/report
func (h *Handler) IngestReport(c *gin.Context) {
	var req models.IngestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()

	project, err := h.repo.UpsertProject(ctx, req.ProjectName, req.Owner, req.Environment)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upsert project"})
		return
	}

	// Extraire le digest depuis les metadata
	digest := ""
	if req.Report.Metadata != nil && len(req.Report.Metadata.RepoDigests) > 0 {
		digest = req.Report.Metadata.RepoDigests[0]
	}

	rawJSON, _ := json.Marshal(req.Report)
	scan, err := h.repo.CreateScan(ctx, project.ID, req.Report.ArtifactName, digest, rawJSON)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create scan"})
		return
	}

	// Aplatir toutes les vulnérabilités des résultats
	var vulns []models.DBVulnerability
	for _, result := range req.Report.Results {
		for _, v := range result.Vulnerabilities {
			vulns = append(vulns, models.DBVulnerability{
				ScanID:           scan.ID,
				CVEID:            v.VulnerabilityID,
				Severity:         v.Severity,
				PackageName:      v.PkgName,
				InstalledVersion: v.InstalledVersion,
				FixedVersion:     v.FixedVersion,
				Title:            v.Title,
				IsFixed:          v.FixedVersion != "",
			})
		}
	}

	if err := h.repo.BulkInsertVulnerabilities(ctx, scan.ID, vulns); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to insert vulnerabilities"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"scan_id":                scan.ID,
		"project":                project.Name,
		"vulnerabilities_stored": len(vulns),
	})
}

// GET /api/v1/projects
func (h *Handler) ListProjects(c *gin.Context) {
	summaries, err := h.repo.ListProjects(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list projects"})
		return
	}
	c.JSON(http.StatusOK, summaries)
}

// GET /api/v1/projects/:name/diff
func (h *Handler) GetDiff(c *gin.Context) {
	name := c.Param("name")
	ctx := c.Request.Context()

	project, err := h.repo.GetProjectByName(ctx, name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
		return
	}

	scans, err := h.repo.GetLastTwoScans(ctx, project.ID)
	if err != nil || len(scans) < 2 {
		c.JSON(http.StatusOK, gin.H{"message": "not enough scans to compute diff", "scans": len(scans)})
		return
	}

	current, err := h.repo.GetVulnerabilitiesByScan(ctx, scans[0].ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get current scan"})
		return
	}
	previous, err := h.repo.GetVulnerabilitiesByScan(ctx, scans[1].ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get previous scan"})
		return
	}

	currentSet := make(map[string]bool)
	for _, v := range current {
		currentSet[v.CVEID+v.PackageName] = true
	}
	previousSet := make(map[string]bool)
	for _, v := range previous {
		previousSet[v.CVEID+v.PackageName] = true
	}

	var newVulns, resolvedVulns []models.DBVulnerability
	for _, v := range current {
		if !previousSet[v.CVEID+v.PackageName] {
			newVulns = append(newVulns, v)
		}
	}
	for _, v := range previous {
		if !currentSet[v.CVEID+v.PackageName] {
			resolvedVulns = append(resolvedVulns, v)
		}
	}

	c.JSON(http.StatusOK, models.DiffResult{
		NewVulnerabilities:      newVulns,
		ResolvedVulnerabilities: resolvedVulns,
		PreviousScanID:          scans[1].ID,
		CurrentScanID:           scans[0].ID,
	})
}

// GET /api/v1/projects/:name/scans
func (h *Handler) GetScans(c *gin.Context) {
	name := c.Param("name")
	ctx := c.Request.Context()

	project, err := h.repo.GetProjectByName(ctx, name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
		return
	}

	scans, err := h.repo.GetLastTwoScans(ctx, project.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get scans"})
		return
	}
	c.JSON(http.StatusOK, scans)
}

// GET /healthz
func (h *Handler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
