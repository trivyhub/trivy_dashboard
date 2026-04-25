package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/theomorin/trivy-dashboard/internal/auth"
	"github.com/theomorin/trivy-dashboard/internal/models"
)

// POST /api/v1/auth/register
func (h *Handler) Register(c *gin.Context) {
	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()

	org, err := h.repo.CreateOrganization(ctx, req.OrgName)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "organization name already taken"})
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
		return
	}

	user, err := h.repo.CreateUser(ctx, org.ID, req.Email, hash)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "email already in use"})
		return
	}

	token, err := auth.GenerateToken(user.ID, org.ID, user.Email, h.jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	c.JSON(http.StatusCreated, models.AuthResponse{Token: token, User: *user})
}

// POST /api/v1/auth/login
func (h *Handler) Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()

	user, err := h.repo.GetUserByEmail(ctx, req.Email)
	if err != nil || !auth.CheckPassword(req.Password, user.PasswordHash) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	token, err := auth.GenerateToken(user.ID, user.OrganizationID, user.Email, h.jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, models.AuthResponse{Token: token, User: *user})
}
