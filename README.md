# Trivy Dashboard

Un dashboard de sécurité centralisé pour visualiser les rapports [Trivy](https://github.com/aquasecurity/trivy) en temps réel.

![Dashboard](https://img.shields.io/badge/Grafana-dashboard-orange) ![Go](https://img.shields.io/badge/Go-1.23-blue) ![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue) ![Docker](https://img.shields.io/badge/Docker-compose-2496ED)

## Aperçu

Trivy Dashboard collecte les rapports de vulnérabilités de vos pipelines CI/CD et les centralise dans un dashboard Grafana. Vous pouvez filtrer par sévérité, par projet, et identifier en un coup d'œil les failles critiques avec un correctif disponible.

**Ce que vous obtenez :**
- Compteurs en temps réel (CRITICAL / HIGH / MEDIUM / LOW)
- Table complète de toutes les CVE, triée par sévérité et filtrable
- Mise en évidence des "Quick Wins" — CVE critiques avec un correctif disponible
- Historique des scans par projet

## Architecture

```
CI/CD Pipeline
     │
     ▼
trivy image --format json mon-image | trivy-push push --project mon-app
     │
     ▼
API Go (Gin)  ──► PostgreSQL
     │
     ▼
Grafana Dashboard
```

## Prérequis

- [Docker](https://www.docker.com/products/docker-desktop) & Docker Compose
- [Go 1.23+](https://go.dev/dl/) (pour compiler la CLI)
- [Trivy](https://aquasecurity.github.io/trivy/) installé dans vos pipelines

---

## Installation

### 1. Cloner le projet

```bash
git clone https://github.com/theo-mrn/trivy_dashboard.git
cd trivy_dashboard
```

### 2. Lancer le stack

```bash
make up
```

Cela démarre :
- **PostgreSQL** sur le port `5432`
- **L'API Go** sur le port `8080`
- **Grafana** sur le port `3000`

### 3. Accéder au dashboard

Ouvrir [http://localhost:3000](http://localhost:3000)

- Login : `admin`
- Mot de passe : `admin`

Le dashboard **Trivy Security Dashboard** est pré-configuré et prêt à l'emploi.

---

## CLI — trivy-push

`trivy-push` est la CLI qui permet d'envoyer un rapport Trivy vers le dashboard depuis n'importe quelle pipeline.

### Installation

**Mac (Apple Silicon)**
```bash
curl -L https://github.com/theo-mrn/trivy_dashboard/releases/latest/download/trivy-push-darwin-arm64 -o trivy-push
chmod +x trivy-push && sudo mv trivy-push /usr/local/bin/
```

**Mac (Intel)**
```bash
curl -L https://github.com/theo-mrn/trivy_dashboard/releases/latest/download/trivy-push-darwin-amd64 -o trivy-push
chmod +x trivy-push && sudo mv trivy-push /usr/local/bin/
```

**Linux (amd64)**
```bash
curl -L https://github.com/theo-mrn/trivy_dashboard/releases/latest/download/trivy-push-linux-amd64 -o trivy-push
chmod +x trivy-push && sudo mv trivy-push /usr/local/bin/
```

### Configuration

Une seule fois, pointez la CLI vers votre dashboard :

```bash
trivy-push config --url http://localhost:8080 --key changeme
```

La config est sauvegardée dans `~/.trivy-push.json`.

### Utilisation

```bash
# Depuis stdin (pipe direct depuis trivy)
trivy image --format json mon-image:latest | trivy-push push --project mon-app

# Depuis un fichier
trivy-push push --project mon-app --file report.json

# Avec toutes les options
trivy-push push \
  --project mon-app \
  --env production \
  --owner team-backend \
  --file report.json
```

**Options disponibles :**

| Option | Alias | Description | Défaut |
|--------|-------|-------------|--------|
| `--project` | `-p` | Nom du projet **(obligatoire)** | — |
| `--env` | `-e` | Environnement (`production`, `staging`, `development`) | `production` |
| `--owner` | `-o` | Équipe propriétaire | — |
| `--file` | `-f` | Fichier JSON Trivy (sinon stdin) | stdin |

---

## Intégration CI/CD

### GitHub Actions

```yaml
name: Security Scan

on:
  push:
    branches: [main]

jobs:
  trivy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build image
        run: docker build -t my-app:${{ github.sha }} .

      - name: Install trivy-push
        run: |
          curl -L https://github.com/theo-mrn/trivy_dashboard/releases/latest/download/trivy-push-linux-amd64 -o trivy-push
          chmod +x trivy-push && sudo mv trivy-push /usr/local/bin/
          trivy-push config --url ${{ secrets.DASHBOARD_URL }} --key ${{ secrets.DASHBOARD_API_KEY }}

      - name: Scan & Upload
        run: |
          trivy image --format json my-app:${{ github.sha }} | \
            trivy-push push --project ${{ github.repository }} --env production
```

### GitLab CI

```yaml
security-scan:
  stage: test
  script:
    - curl -L https://github.com/theo-mrn/trivy_dashboard/releases/latest/download/trivy-push-linux-amd64 -o /usr/local/bin/trivy-push
    - chmod +x /usr/local/bin/trivy-push
    - trivy-push config --url $DASHBOARD_URL --key $DASHBOARD_API_KEY
    - trivy image --format json $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA | trivy-push push --project $CI_PROJECT_NAME
```

---

## API

L'API accepte les rapports Trivy en JSON.

### POST /api/v1/report

Envoie un rapport de scan.

**Headers**
```
Content-Type: application/json
X-API-Key: <votre-api-key>
```

**Body**
```json
{
  "project_name": "mon-app",
  "environment": "production",
  "owner": "team-backend",
  "report": { /* rapport JSON Trivy */ }
}
```

**Réponse**
```json
{
  "scan_id": 42,
  "project": "mon-app",
  "vulnerabilities_stored": 17
}
```

### GET /api/v1/projects

Liste tous les projets avec leur résumé de vulnérabilités.

### GET /api/v1/projects/:name/diff

Compare les deux derniers scans d'un projet et retourne les CVE nouvelles et résolues.

### GET /healthz

Healthcheck de l'API.

---

## Configuration

### Variables d'environnement (API)

| Variable | Description | Défaut |
|----------|-------------|--------|
| `DATABASE_URL` | URL de connexion PostgreSQL | — |
| `API_KEY` | Clé d'authentification de l'API | — |
| `PORT` | Port d'écoute | `8080` |

### Fichier .env

```bash
cp .env.example .env
```

```env
API_KEY=changeme
GRAFANA_PASSWORD=admin
```

---

## Commandes utiles

```bash
make up                 # Démarrer le stack
make down               # Arrêter le stack
make logs               # Voir les logs de l'API
make send-test-report   # Envoyer un rapport de test
make db-shell           # Ouvrir un shell PostgreSQL
```

---

## Stack technique

| Composant | Technologie |
|-----------|-------------|
| Backend | Go 1.23 + Gin |
| Base de données | PostgreSQL 16 |
| Visualisation | Grafana 10 |
| CLI | Go + Cobra |
| Conteneurisation | Docker Compose |
