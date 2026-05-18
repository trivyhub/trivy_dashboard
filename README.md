# TrivyHub — Backend API

Centralized vulnerability management platform. Collects Trivy scan reports from CI/CD pipelines and exposes them via a REST API.

![Go](https://img.shields.io/badge/Go-1.23-blue) ![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue) ![Docker](https://img.shields.io/badge/Docker-ready-2496ED)

**Live API:** https://api.trivyhub.fr  
**Dashboard:** https://dashboard.trivyhub.fr

---

---

## Architecture

```
CI/CD Pipeline
     │
     │  trivy image --format json my-image | trivy-push push --project my-app
     ▼
Go API (port 8080)  ──►  PostgreSQL
     ▲
     │  REST API
Next.js Frontend (separate repo)
```

---

## Quick start

### Prerequisites

- Docker & Docker Compose

### Run locally

```bash
git clone https://github.com/trivyhub/trivy_dashboard.git
cd trivy_dashboard
docker compose up -d
```

API available at **http://localhost:8080**

### Create an account & get an API key

Go to **https://dashboard.trivyhub.fr** → Register → Settings → API Keys.

The key (`tvd_xxx...`) is shown **only once** — copy it immediately.

---

## trivy-push CLI

Push Trivy reports to the dashboard from any pipeline.

### Install

**Mac Apple Silicon**
```bash
curl -L https://github.com/trivyhub/trivy_dashboard/releases/latest/download/trivy-push-darwin-arm64 -o trivy-push
chmod +x trivy-push && sudo mv trivy-push /usr/local/bin/
```

**Mac Intel**
```bash
curl -L https://github.com/trivyhub/trivy_dashboard/releases/latest/download/trivy-push-darwin-amd64 -o trivy-push
chmod +x trivy-push && sudo mv trivy-push /usr/local/bin/
```

**Linux**
```bash
curl -L https://github.com/trivyhub/trivy_dashboard/releases/latest/download/trivy-push-linux-amd64 -o trivy-push
chmod +x trivy-push && sudo mv trivy-push /usr/local/bin/
```

### Configure (once)

```bash
trivy-push config --url https://api.trivyhub.fr --key tvd_xxx
```

Config saved in `~/.trivy-push.json`.

### Usage

```bash
# Pipe from Trivy
trivy image --format json my-image:latest | trivy-push push --project my-app

# From file
trivy-push push --project my-app --file report.json

# Check connectivity
trivy-push status
```

| Flag | Alias | Description | Default |
|------|-------|-------------|---------|
| `--project` | `-p` | Project name **(required)** | — |
| `--env` | `-e` | Environment (auto-detected from branch) | auto |
| `--owner` | `-o` | Team owner | — |
| `--file` | `-f` | JSON file (or stdin) | stdin |

**Environment auto-detection:**
- Branch `main` / `master` → `production`
- Branch `develop` / `dev` → `staging`
- Other branches → `development`

**CI auto-detection:** Pipeline ID and URL are automatically read from GitHub Actions, GitLab CI, CircleCI, Jenkins, Bitbucket, Azure DevOps — no manual flags needed.

---

## GitHub Action (recommended)

Use the reusable action in any repo — 2 lines:

```yaml
- name: Scan & push to TrivyHub
  uses: trivyhub/trivy-push-action@v1
  with:
    image: my-org/my-app:latest
    api-key: ${{ secrets.TRIVYHUB_API_KEY }}
```

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `image` | ✓ | — | Docker image to scan |
| `api-key` | ✓ | — | TrivyHub API key |
| `project` | — | `github.repository` | Project name |
| `environment` | — | `production` | Environment |
| `url` | — | `https://api.trivyhub.fr` | API URL |

### GitLab CI

```yaml
security-scan:
  script:
    - curl -L https://github.com/trivyhub/trivy_dashboard/releases/latest/download/trivy-push-linux-amd64 -o /usr/local/bin/trivy-push
    - chmod +x /usr/local/bin/trivy-push
    - trivy-push config --url $TRIVYHUB_URL --key $TRIVYHUB_API_KEY
    - trivy image --format json $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA | trivy-push push --project $CI_PROJECT_NAME
```

---

## Roles & permissions

| Action | viewer | member | admin | owner |
|--------|--------|--------|-------|-------|
| View CVEs / projects | ✓ | ✓ | ✓ | ✓ |
| Push report | ✗ | ✓ | ✓ | ✓ |
| Manage API keys | ✗ | ✗ | ✓ | ✓ |
| Invite members | ✗ | ✗ | ✓ | ✓ |
| Change roles | ✗ | ✗ | ✗ | ✓ |
| Remove members | ✗ | ✗ | ✗ | ✓ |

---

## API Reference

Full spec: [`api/openapi.yaml`](api/openapi.yaml)

### Authentication

```
Authorization: Bearer <jwt>      # Web app
Authorization: ApiKey tvd_xxx    # CI/CD pipelines
```

### Endpoints

| Method | Endpoint | Role | Description |
|--------|----------|------|-------------|
| GET | `/healthz` | — | Health check |
| POST | `/api/v1/auth/register` | — | Create org + owner account |
| POST | `/api/v1/auth/login` | — | Sign in |
| GET | `/api/v1/auth/me` | any | Current user |
| PUT | `/api/v1/auth/password` | any | Change password |
| POST | `/api/v1/report` | member+ | Ingest Trivy report |
| GET | `/api/v1/projects` | viewer+ | List projects |
| GET | `/api/v1/projects/scans?name=` | viewer+ | Scan history for a project |
| GET | `/api/v1/projects/diff?name=` | viewer+ | Diff between last two scans |
| GET | `/api/v1/scans/:id/vulnerabilities` | viewer+ | CVEs for a specific scan |
| GET | `/api/v1/vulnerabilities` | viewer+ | Latest CVEs (paginated) |
| GET | `/api/v1/members` | viewer+ | List members |
| POST | `/api/v1/members/invite` | admin+ | Invite member |
| PUT | `/api/v1/members/:id/role` | owner | Update role |
| DELETE | `/api/v1/members/:id` | owner | Remove member |
| GET | `/api/v1/api-keys` | admin+ | List API keys |
| POST | `/api/v1/api-keys` | admin+ | Create API key |
| DELETE | `/api/v1/api-keys/:id` | admin+ | Revoke API key |

### Pagination

`GET /api/v1/vulnerabilities?page=1&limit=100&severity=CRITICAL`

---

## Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | required |
| `JWT_SECRET` | JWT signing secret | `dev-secret-change-in-prod` |
| `MIGRATIONS_DIR` | Path to SQL migrations | `migrations` |
| `PORT` | Listen port | `8080` |

---

## Production deployment

```bash
# Create network
docker network create trivy-net

# PostgreSQL
docker run -d --name postgres --network trivy-net \
  -e POSTGRES_USER=trivy -e POSTGRES_PASSWORD=trivy -e POSTGRES_DB=trivy \
  postgres:16-alpine

# API (migrations run automatically on startup)
docker run -d --name trivy-dashboard --network trivy-net \
  -p 8080:8080 \
  -e DATABASE_URL="postgres://trivy:trivy@postgres:5432/trivy" \
  -e JWT_SECRET="your-secret" \
  trivyhub/trivy-dashboard:latest
```

---

## Stack

| Component | Technology |
|-----------|------------|
| API | Go 1.23 + Gin |
| Database | PostgreSQL 16 |
| CLI | Go + Cobra |
| Auth | JWT + API keys |
| Rate limiting | 60 req/min per IP |
| Migrations | Auto-run at startup |
