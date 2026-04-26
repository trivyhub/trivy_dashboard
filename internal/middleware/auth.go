package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/theomorin/trivy-dashboard/internal/auth"
	"github.com/theomorin/trivy-dashboard/internal/repository"
)

const ClaimsKey = "claims"

func JWTAuth(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if header == "" || !strings.HasPrefix(header, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing Authorization header"})
			return
		}
		claims, err := auth.ParseToken(strings.TrimPrefix(header, "Bearer "), secret)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		c.Set(ClaimsKey, claims)
		c.Next()
	}
}

// Auth accepte soit un JWT (site web) soit une API key (pipeline)
func Auth(secret string, repo *repository.Repository) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")

		// JWT
		if strings.HasPrefix(header, "Bearer ") {
			claims, err := auth.ParseToken(strings.TrimPrefix(header, "Bearer "), secret)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
				return
			}
			c.Set(ClaimsKey, claims)
			c.Next()
			return
		}

		// API Key
		if strings.HasPrefix(header, "ApiKey ") {
			rawKey := strings.TrimPrefix(header, "ApiKey ")
			sum := sha256.Sum256([]byte(rawKey))
			hash := hex.EncodeToString(sum[:])

			apiKey, err := repo.GetAPIKeyByHash(context.Background(), hash)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid api key"})
				return
			}

			go repo.TouchAPIKey(context.Background(), apiKey.ID)

			c.Set(ClaimsKey, &auth.Claims{
				UserID:         0,
				OrganizationID: apiKey.OrganizationID,
				Email:          "",
				Role:           "member",
			})
			c.Next()
			return
		}

		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization"})
	}
}

func ClaimsFromCtx(c *gin.Context) *auth.Claims {
	v, _ := c.Get(ClaimsKey)
	claims, _ := v.(*auth.Claims)
	return claims
}

// RequireRole bloque si le rôle du user est insuffisant
func RequireRole(roles ...string) gin.HandlerFunc {
	allowed := make(map[string]bool)
	for _, r := range roles {
		allowed[r] = true
	}
	return func(c *gin.Context) {
		claims := ClaimsFromCtx(c)
		if claims == nil || !allowed[claims.Role] {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			return
		}
		c.Next()
	}
}
