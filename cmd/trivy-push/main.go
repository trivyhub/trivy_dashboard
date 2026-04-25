package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

type Config struct {
	URL    string `json:"url"`
	APIKey string `json:"api_key"`
}

type PushPayload struct {
	ProjectName string          `json:"project_name"`
	Environment string          `json:"environment"`
	Owner       string          `json:"owner"`
	PipelineID  string          `json:"pipeline_id,omitempty"`
	PipelineURL string          `json:"pipeline_url,omitempty"`
	Report      json.RawMessage `json:"report"`
}

type CIInfo struct {
	Provider    string
	PipelineID  string
	PipelineURL string
}

// detectCI lit les variables d'environnement standard des principaux CI.
func detectCI() CIInfo {
	// GitHub Actions
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		runID := os.Getenv("GITHUB_RUN_ID")
		repo := os.Getenv("GITHUB_REPOSITORY")
		serverURL := os.Getenv("GITHUB_SERVER_URL")
		url := ""
		if repo != "" && runID != "" {
			url = serverURL + "/" + repo + "/actions/runs/" + runID
		}
		return CIInfo{Provider: "github", PipelineID: runID, PipelineURL: url}
	}
	// GitLab CI
	if os.Getenv("GITLAB_CI") == "true" {
		id := os.Getenv("CI_PIPELINE_ID")
		url := os.Getenv("CI_PIPELINE_URL")
		return CIInfo{Provider: "gitlab", PipelineID: id, PipelineURL: url}
	}
	// CircleCI
	if os.Getenv("CIRCLECI") == "true" {
		id := os.Getenv("CIRCLE_WORKFLOW_ID")
		url := os.Getenv("CIRCLE_BUILD_URL")
		return CIInfo{Provider: "circleci", PipelineID: id, PipelineURL: url}
	}
	// Jenkins
	if os.Getenv("JENKINS_URL") != "" {
		id := os.Getenv("BUILD_NUMBER")
		url := os.Getenv("BUILD_URL")
		return CIInfo{Provider: "jenkins", PipelineID: id, PipelineURL: url}
	}
	// Bitbucket Pipelines
	if os.Getenv("BITBUCKET_PIPELINE_UUID") != "" {
		id := os.Getenv("BITBUCKET_BUILD_NUMBER")
		url := ""
		if ws := os.Getenv("BITBUCKET_WORKSPACE"); ws != "" {
			repo := os.Getenv("BITBUCKET_REPO_SLUG")
			url = "https://bitbucket.org/" + ws + "/" + repo + "/pipelines/" + id
		}
		return CIInfo{Provider: "bitbucket", PipelineID: id, PipelineURL: url}
	}
	// Azure DevOps
	if os.Getenv("TF_BUILD") == "True" {
		id := os.Getenv("BUILD_BUILDNUMBER")
		url := os.Getenv("SYSTEM_TEAMFOUNDATIONSERVERURI") + os.Getenv("SYSTEM_TEAMPROJECT") + "/_build/results?buildId=" + os.Getenv("BUILD_BUILDID")
		return CIInfo{Provider: "azure", PipelineID: id, PipelineURL: url}
	}
	return CIInfo{}
}

func configPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".trivy-push.json")
}

func loadConfig() (Config, error) {
	var cfg Config
	data, err := os.ReadFile(configPath())
	if err != nil {
		return cfg, fmt.Errorf("config introuvable — lance d'abord: trivy-push config --url ... --key ...")
	}
	err = json.Unmarshal(data, &cfg)
	return cfg, err
}

func doRequest(method, url, auth string, body []byte) (*http.Response, []byte, error) {
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", auth)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("erreur réseau: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp, respBody, nil
}

func main() {
	root := &cobra.Command{
		Use:   "trivy-push",
		Short: "CLI pour envoyer des rapports Trivy vers le dashboard",
	}

	// ── config ────────────────────────────────────────────────────────────────
	var cfgURL, cfgKey string
	cmdConfig := &cobra.Command{
		Use:   "config",
		Short: "Configurer l'URL et la clé API",
		Example: `  trivy-push config --url https://mon-dashboard.com --key tvd_abc123`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := Config{URL: cfgURL, APIKey: cfgKey}
			data, _ := json.MarshalIndent(cfg, "", "  ")
			if err := os.WriteFile(configPath(), data, 0600); err != nil {
				return err
			}
			fmt.Printf("✓ Config sauvegardée dans %s\n", configPath())
			return nil
		},
	}
	cmdConfig.Flags().StringVar(&cfgURL, "url", "", "URL du dashboard (ex: https://mon-dashboard.com)")
	cmdConfig.Flags().StringVar(&cfgKey, "key", "", "Clé API générée depuis le dashboard")
	cmdConfig.MarkFlagRequired("url")
	cmdConfig.MarkFlagRequired("key")

	// ── push ──────────────────────────────────────────────────────────────────
	var project, env, owner, file string
	cmdPush := &cobra.Command{
		Use:   "push",
		Short: "Envoyer un rapport Trivy",
		Example: `  trivy image --format json mon-image:latest | trivy-push push --project mon-app
  trivy-push push --project mon-app --file report.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}

			var raw []byte
			if file != "" {
				raw, err = os.ReadFile(file)
				if err != nil {
					return fmt.Errorf("impossible de lire %s: %w", file, err)
				}
			} else {
				raw, err = io.ReadAll(os.Stdin)
				if err != nil {
					return fmt.Errorf("erreur lecture stdin: %w", err)
				}
			}

			if len(raw) == 0 {
				return fmt.Errorf("aucun rapport reçu — utilise --file ou pipe depuis trivy")
			}

			ci := detectCI()
			if ci.Provider != "" {
				fmt.Printf("⚡ CI détecté: %s (pipeline %s)\n", ci.Provider, ci.PipelineID)
			}

			payload := PushPayload{
				ProjectName: project,
				Environment: env,
				Owner:       owner,
				PipelineID:  ci.PipelineID,
				PipelineURL: ci.PipelineURL,
				Report:      json.RawMessage(raw),
			}
			body, _ := json.Marshal(payload)

			resp, respBody, err := doRequest("POST", cfg.URL+"/api/v1/report", "ApiKey "+cfg.APIKey, body)
			if err != nil {
				return err
			}
			if resp.StatusCode != http.StatusCreated {
				return fmt.Errorf("erreur %d: %s", resp.StatusCode, string(respBody))
			}

			var result map[string]any
			json.Unmarshal(respBody, &result)
			fmt.Printf("✓ Rapport envoyé — projet: %s, scan_id: %v, CVE stockées: %v\n",
				result["project"], result["scan_id"], result["vulnerabilities_stored"])
			return nil
		},
	}
	cmdPush.Flags().StringVarP(&project, "project", "p", "", "Nom du projet (obligatoire)")
	cmdPush.Flags().StringVarP(&env, "env", "e", "production", "Environnement")
	cmdPush.Flags().StringVarP(&owner, "owner", "o", "", "Équipe propriétaire")
	cmdPush.Flags().StringVarP(&file, "file", "f", "", "Fichier JSON Trivy (sinon stdin)")
	cmdPush.MarkFlagRequired("project")

	root.AddCommand(cmdConfig, cmdPush)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
