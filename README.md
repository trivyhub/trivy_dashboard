# Trivy Dashboard

Plateforme centralisée pour collecter et visualiser les rapports de vulnérabilités [Trivy](https://github.com/aquasecurity/trivy) par organisation et par projet.

![Go](https://img.shields.io/badge/Go-1.23-blue) ![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue) ![Docker](https://img.shields.io/badge/Docker-compose-2496ED)

---

## Architecture

```
Pipeline CI/CD
     │
     │  trivy image --format json mon-image | trivy-push push --project mon-app
     ▼
API Go (port 8080)  ──►  PostgreSQL
     ▲
     │  REST API
Frontend Next.js (repo séparé)
```

Chaque organisation a ses propres projets, scans et membres. Les données sont totalement isolées entre organisations.

---

## Démarrage rapide

### Prérequis

- [Docker](https://www.docker.com/products/docker-desktop) & Docker Compose

### Lancer le stack

```bash
git clone https://github.com/theo-mrn/trivy_dashboard.git
cd trivy_dashboard
docker compose up -d
```

L'API est disponible sur **http://localhost:8080**

### Créer un compte

```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"org_name":"mon-org","email":"admin@mon-org.com","password":"motdepasse"}'
```

### Créer une clé API pour les pipelines

```bash
curl -X POST http://localhost:8080/api/v1/api-keys \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"name":"github-actions"}'
```

La clé retournée (`tvd_xxx...`) n'est affichée **qu'une seule fois**.

---

## CLI — trivy-push

`trivy-push` est la CLI qui envoie les rapports Trivy vers le dashboard depuis n'importe quelle pipeline.

### Installation

**Mac Apple Silicon**
```bash
curl -L https://github.com/theo-mrn/trivy_dashboard/releases/latest/download/trivy-push-darwin-arm64 -o trivy-push
chmod +x trivy-push && sudo mv trivy-push /usr/local/bin/
```

**Mac Intel**
```bash
curl -L https://github.com/theo-mrn/trivy_dashboard/releases/latest/download/trivy-push-darwin-amd64 -o trivy-push
chmod +x trivy-push && sudo mv trivy-push /usr/local/bin/
```

**Linux**
```bash
curl -L https://github.com/theo-mrn/trivy_dashboard/releases/latest/download/trivy-push-linux-amd64 -o trivy-push
chmod +x trivy-push && sudo mv trivy-push /usr/local/bin/
```

### Configuration (une seule fois)

```bash
trivy-push config --url https://ton-dashboard.com --key tvd_xxx
```

La config est sauvegardée dans `~/.trivy-push.json`.

### Utilisation

```bash
# Pipe direct depuis Trivy
trivy image --format json mon-image:latest | trivy-push push --project mon-app

# Depuis un fichier
trivy-push push --project mon-app --file report.json

# Avec toutes les options
trivy-push push --project mon-app --env production --owner team-backend --file report.json
```

| Option | Alias | Description | Défaut |
|--------|-------|-------------|--------|
| `--project` | `-p` | Nom du projet **(obligatoire)** | — |
| `--env` | `-e` | Environnement | `production` |
| `--owner` | `-o` | Équipe propriétaire | — |
| `--file` | `-f` | Fichier JSON (sinon stdin) | stdin |

---

## Intégration CI/CD

### GitHub Actions

```yaml
- name: Install trivy-push
  run: |
    curl -L https://github.com/theo-mrn/trivy_dashboard/releases/latest/download/trivy-push-linux-amd64 -o trivy-push
    chmod +x trivy-push && sudo mv trivy-push /usr/local/bin/
    trivy-push config --url ${{ secrets.DASHBOARD_URL }} --key ${{ secrets.DASHBOARD_API_KEY }}

- name: Scan & Upload
  run: |
    trivy image --format json mon-image:${{ github.sha }} | \
      trivy-push push --project ${{ github.repository }}
```

### GitLab CI

```yaml
security-scan:
  script:
    - curl -L https://github.com/theo-mrn/trivy_dashboard/releases/latest/download/trivy-push-linux-amd64 -o /usr/local/bin/trivy-push
    - chmod +x /usr/local/bin/trivy-push
    - trivy-push config --url $DASHBOARD_URL --key $DASHBOARD_API_KEY
    - trivy image --format json $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA | trivy-push push --project $CI_PROJECT_NAME
```

---

## Rôles et permissions

| Action | viewer | member | admin | owner |
|--------|--------|--------|-------|-------|
| Voir CVE / projets | ✓ | ✓ | ✓ | ✓ |
| Push rapport | ✗ | ✓ | ✓ | ✓ |
| Gérer les clés API | ✗ | ✗ | ✓ | ✓ |
| Inviter des membres | ✗ | ✗ | ✓ | ✓ |
| Changer les rôles | ✗ | ✗ | ✗ | ✓ |
| Supprimer des membres | ✗ | ✗ | ✗ | ✓ |

---

## API

La documentation complète est disponible dans [`api/openapi.yaml`](api/openapi.yaml).

### Authentification

Deux méthodes selon le contexte :

**JWT** — pour le site web
```
Authorization: Bearer <token>
```

**Clé API** — pour les pipelines CI/CD
```
Authorization: ApiKey tvd_xxx...
```

### Endpoints

| Méthode | Endpoint | Rôle requis | Description |
|---------|----------|-------------|-------------|
| GET | `/healthz` | — | Healthcheck |
| POST | `/api/v1/auth/register` | — | Créer org + compte owner |
| POST | `/api/v1/auth/login` | — | Se connecter |
| GET | `/api/v1/auth/me` | tous | User connecté |
| PUT | `/api/v1/auth/password` | tous | Changer mot de passe |
| POST | `/api/v1/report` | member+ | Envoyer un rapport Trivy |
| GET | `/api/v1/projects` | viewer+ | Lister les projets |
| GET | `/api/v1/projects/:name/diff` | viewer+ | Diff entre deux scans |
| GET | `/api/v1/vulnerabilities` | viewer+ | Toutes les CVE |
| GET | `/api/v1/members` | viewer+ | Lister les membres |
| POST | `/api/v1/members/invite` | admin+ | Inviter un membre |
| PUT | `/api/v1/members/:id/role` | owner | Changer un rôle |
| DELETE | `/api/v1/members/:id` | owner | Supprimer un membre |
| GET | `/api/v1/api-keys` | admin+ | Lister les clés API |
| POST | `/api/v1/api-keys` | admin+ | Créer une clé API |
| DELETE | `/api/v1/api-keys/:id` | admin+ | Révoquer une clé API |

---

## Variables d'environnement

| Variable | Description | Défaut |
|----------|-------------|--------|
| `DATABASE_URL` | URL PostgreSQL | — |
| `JWT_SECRET` | Secret pour signer les JWT | `dev-secret-change-in-prod` |
| `PORT` | Port d'écoute | `8080` |

---

## Commandes utiles

```bash
make up          # Démarrer le stack
make down        # Arrêter le stack
make logs        # Logs de l'API
make db-shell    # Shell PostgreSQL
```

---

## Stack technique

| Composant | Technologie |
|-----------|-------------|
| Backend | Go 1.23 + Gin |
| Base de données | PostgreSQL 16 |
| CLI | Go + Cobra |
| Conteneurisation | Docker Compose |
| Frontend | Next.js (repo séparé) |
