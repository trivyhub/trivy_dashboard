.PHONY: up down build logs ps migrate seed test lint

# ── Docker ────────────────────────────────────────────────────────────────────
up:
	docker compose up --build -d

down:
	docker compose down

build:
	docker compose build

logs:
	docker compose logs -f api

ps:
	docker compose ps

# ── Dev local ─────────────────────────────────────────────────────────────────
run:
	go run ./cmd/api/...

test:
	go test ./... -v -count=1

lint:
	golangci-lint run ./...

# ── Base de données ───────────────────────────────────────────────────────────
migrate:
	docker compose exec postgres psql -U trivy -d trivy_dashboard -f /docker-entrypoint-initdb.d/001_init.sql

db-shell:
	docker compose exec postgres psql -U trivy -d trivy_dashboard

# ── Utilitaires ───────────────────────────────────────────────────────────────
# Envoyer un rapport de test à l'API locale
send-test-report:
	@echo "Envoi du rapport de test..."
	curl -s -X POST http://localhost:8080/api/v1/report \
		-H "Content-Type: application/json" \
		-H "X-API-Key: changeme" \
		-d @testdata/sample_report.json | jq .

# Créer un .env depuis le template
env:
	cp .env.example .env
	@echo ".env créé — pense à modifier API_KEY et GRAFANA_PASSWORD"
