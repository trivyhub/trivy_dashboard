package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/theomorin/trivy-dashboard/internal/models"
)

func generateKey() (full, prefix, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	full = "tvd_" + hex.EncodeToString(b)
	prefix = full[:10]
	sum := sha256.Sum256([]byte(full))
	hash = hex.EncodeToString(sum[:])
	return
}

// POST /api/v1/api-keys
func (h *Handler) CreateAPIKey(c *gin.Context) {
	claims := claimsFromCtx(c)

	var req models.CreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	full, prefix, hash, err := generateKey()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate key"})
		return
	}

	key, err := h.repo.CreateAPIKey(c.Request.Context(), claims.OrganizationID, req.Name, hash, prefix)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create api key"})
		return
	}

	c.JSON(http.StatusCreated, models.CreateAPIKeyResponse{
		APIKey: *key,
		Key:    full,
	})
}

// GET /api/v1/api-keys
func (h *Handler) ListAPIKeys(c *gin.Context) {
	claims := claimsFromCtx(c)
	keys, err := h.repo.ListAPIKeys(c.Request.Context(), claims.OrganizationID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list api keys"})
		return
	}
	c.JSON(http.StatusOK, keys)
}

// DELETE /api/v1/api-keys/:id
func (h *Handler) RevokeAPIKey(c *gin.Context) {
	claims := claimsFromCtx(c)
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	if err := h.repo.RevokeAPIKey(c.Request.Context(), claims.OrganizationID, id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke key"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("key %d revoked", id)})
}
