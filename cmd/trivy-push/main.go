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
	Report      json.RawMessage `json:"report"`
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

			payload := PushPayload{
				ProjectName: project,
				Environment: env,
				Owner:       owner,
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
