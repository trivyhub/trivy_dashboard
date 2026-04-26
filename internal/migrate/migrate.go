package migrate

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

func Run(ctx context.Context, db *pgxpool.Pool, dir string) error {
	_, err := db.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			filename TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	if err != nil {
		return err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	for _, f := range files {
		var exists bool
		db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE filename=$1)`, f).Scan(&exists)
		if exists {
			continue
		}

		sql, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			return err
		}

		if _, err := db.Exec(ctx, string(sql)); err != nil {
			return err
		}

		db.Exec(ctx, `INSERT INTO schema_migrations (filename) VALUES ($1)`, f)
		log.Printf("migration applied: %s", f)
	}
	return nil
}
