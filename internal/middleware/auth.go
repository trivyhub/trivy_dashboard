package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func APIKeyAuth(apiKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.GetHeader("X-API-Key")
		if key == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing X-API-Key header"})
			return
		}
		if key != apiKey {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid API key"})
			return
		}
		c.Next()
	}
}
