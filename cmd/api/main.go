package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	limiter "github.com/ulule/limiter/v3"
	limitergin "github.com/ulule/limiter/v3/drivers/middleware/gin"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	"github.com/theomorin/trivy-dashboard/internal/handlers"
	"github.com/theomorin/trivy-dashboard/internal/middleware"
	"github.com/theomorin/trivy-dashboard/internal/migrate"
	"github.com/theomorin/trivy-dashboard/internal/models"
	"github.com/theomorin/trivy-dashboard/internal/repository"
)

func main() {
	_ = godotenv.Load()

	dbURL := mustEnv("DATABASE_URL")
	jwtSecret := getEnv("JWT_SECRET", "dev-secret-change-in-prod")
	migrationsDir := getEnv("MIGRATIONS_DIR", "migrations")
	port := getEnv("PORT", "8080")

	db, err := connectDB(dbURL)
	if err != nil {
		log.Fatalf("cannot connect to database: %v", err)
	}
	defer db.Close()

	if err := migrate.Run(context.Background(), db, migrationsDir); err != nil {
		log.Fatalf("migrations failed: %v", err)
	}

	// Rate limiter: 60 req/min par IP
	rate, _ := limiter.NewRateFromFormatted("60-M")
	store := memory.NewStore()
	rateLimiter := limitergin.NewMiddleware(limiter.New(store, rate))

	repo := repository.New(db)
	h := handlers.New(repo, jwtSecret)

	r := gin.Default()
	r.Use(rateLimiter)
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Authorization,Content-Type")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	r.GET("/healthz", h.Health)

	api := r.Group("/api/v1")
	{
		api.POST("/auth/register", h.Register)
		api.POST("/auth/login", h.Login)
		api.GET("/auth/me", middleware.Auth(jwtSecret, repo), h.Me)
		api.PUT("/auth/password", middleware.Auth(jwtSecret, repo), h.ChangePassword)

		protected := api.Group("/", middleware.Auth(jwtSecret, repo))
		{
			protected.GET("/projects", h.ListProjects)
			protected.GET("/projects/:name/diff", h.GetDiff)
			protected.GET("/projects/:name/scans", h.ListScans)
			protected.GET("/scans/:id/vulnerabilities", h.GetScanVulnerabilities)
			protected.GET("/vulnerabilities", h.ListVulnerabilities)
			protected.GET("/members", h.ListMembers)

			protected.POST("/report", middleware.RequireRole(models.RoleOwner, models.RoleAdmin, models.RoleMember), h.IngestReport)

			protected.POST("/api-keys", middleware.RequireRole(models.RoleOwner, models.RoleAdmin), h.CreateAPIKey)
			protected.GET("/api-keys", middleware.RequireRole(models.RoleOwner, models.RoleAdmin), h.ListAPIKeys)
			protected.DELETE("/api-keys/:id", middleware.RequireRole(models.RoleOwner, models.RoleAdmin), h.RevokeAPIKey)

			protected.POST("/members/invite", middleware.RequireRole(models.RoleOwner, models.RoleAdmin), h.InviteMember)
			protected.PUT("/members/:id/role", middleware.RequireRole(models.RoleOwner), h.UpdateMemberRole)
			protected.DELETE("/members/:id", middleware.RequireRole(models.RoleOwner), h.RemoveMember)
		}
	}

	log.Printf("trivy-dashboard listening on :%s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func connectDB(url string) (*pgxpool.Pool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, err
	}
	log.Println("database connected")
	return pool, nil
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("required env var %s is not set", key)
	}
	return v
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
