package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/theomorin/trivy-dashboard/internal/auth"
	"github.com/theomorin/trivy-dashboard/internal/models"
)

// GET /api/v1/members
func (h *Handler) ListMembers(c *gin.Context) {
	claims := claimsFromCtx(c)
	members, err := h.repo.ListMembers(c.Request.Context(), claims.OrganizationID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list members"})
		return
	}
	c.JSON(http.StatusOK, members)
}

// POST /api/v1/members/invite
func (h *Handler) InviteMember(c *gin.Context) {
	claims := claimsFromCtx(c)

	var req models.InviteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Mot de passe temporaire — l'utilisateur devra le changer
	tempHash, err := auth.HashPassword("ChangeMe123!")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
		return
	}

	user, err := h.repo.CreateUser(c.Request.Context(), claims.OrganizationID, req.Email, tempHash, req.Role)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "email already in use"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"user":             user,
		"temp_password":    "ChangeMe123!",
		"message":          "User invited. Share the temp_password and ask them to change it on first login.",
	})
}

// PUT /api/v1/members/:id/role
func (h *Handler) UpdateMemberRole(c *gin.Context) {
	claims := claimsFromCtx(c)

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	var body struct {
		Role string `json:"role" binding:"required,oneof=admin member viewer"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.repo.UpdateUserRole(c.Request.Context(), claims.OrganizationID, id, body.Role); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update role"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "role updated"})
}

// DELETE /api/v1/members/:id
func (h *Handler) RemoveMember(c *gin.Context) {
	claims := claimsFromCtx(c)

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	if id == claims.UserID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot remove yourself"})
		return
	}

	if err := h.repo.RemoveMember(c.Request.Context(), claims.OrganizationID, id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to remove member"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "member removed"})
}
