package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/theomorin/trivy-dashboard/internal/handlers"
	"github.com/theomorin/trivy-dashboard/internal/middleware"
	"github.com/theomorin/trivy-dashboard/internal/repository"
)

func main() {
	_ = godotenv.Load()

	dbURL := mustEnv("DATABASE_URL")
	apiKey := mustEnv("API_KEY")
	port := getEnv("PORT", "8080")

	db, err := connectDB(dbURL)
	if err != nil {
		log.Fatalf("cannot connect to database: %v", err)
	}
	defer db.Close()

	repo := repository.New(db)
	h := handlers.New(repo)

	r := gin.Default()
	r.GET("/healthz", h.Health)

	api := r.Group("/api/v1", middleware.APIKeyAuth(apiKey))
	{
		api.POST("/report", h.IngestReport)
		api.GET("/projects", h.ListProjects)
		api.GET("/projects/:name/diff", h.GetDiff)
		api.GET("/projects/:name/scans", h.GetScans)
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
