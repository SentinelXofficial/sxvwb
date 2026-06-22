// Package well fetches and synchronizes YAML blueprints from a remote
// repository. Like a community well, everyone draws from it and anyone
// can contribute back.
package well

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ── Types ────────────────────────────────────────────────────────────────

// Repo describes a blueprint source.
type Repo struct {
	Name string `json:"name"`
	URL  string `json:"url"`  // GitHub releases URL for the blueprint bundle
}

// Index is the local catalog of installed blueprints.
type Index struct {
	SyncedAt  time.Time          `json:"synced_at"`
	Repos     []Repo             `json:"repos"`
	Blueprints map[string]BlueprintInfo `json:"blueprints"`
}

// BlueprintInfo tracks one installed blueprint.
type BlueprintInfo struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Level    string   `json:"level"`
	Labels   []string `json:"labels"`
	Source   string   `json:"source"` // which repo it came from
	File     string   `json:"file"`   // local path
}

// ── Default repos ───────────────────────────────────────────────────────

// DefaultRepo is the official sxsc blueprint repository.
var DefaultRepo = Repo{
	Name: "sxsc-blueprints",
	URL:  "https://api.github.com/repos/SentinelXofficial/sxsc-blueprints/releases/latest",
}

// ── Sync ─────────────────────────────────────────────────────────────────

// Pull downloads the latest blueprints from all configured repos and
// installs them into the local template directory.
func Pull(repos []Repo, targetDir string) (*Index, error) {
	if len(repos) == 0 {
		repos = []Repo{DefaultRepo}
	}

	idx := &Index{
		SyncedAt:  time.Now(),
		Repos:     repos,
		Blueprints: make(map[string]BlueprintInfo),
	}

	// Load existing index if it exists
	idxPath := filepath.Join(targetDir, ".blueprint-index.json")
	if data, err := os.ReadFile(idxPath); err == nil {
		json.Unmarshal(data, idx)
	}

	for _, repo := range repos {
		fmt.Printf("  [well] Fetching %s...\n", repo.Name)
		assets, err := fetchReleaseAssets(repo.URL)
		if err != nil {
			fmt.Printf("  [well] %s: %v (skipping)\n", repo.Name, err)
			continue
		}

		for _, asset := range assets {
			if !strings.HasSuffix(asset.Name, ".zip") {
				continue
			}
			fmt.Printf("  [well] Downloading %s (%d bytes)...\n", asset.Name, asset.Size)
			if err := downloadAndExtract(asset.URL, targetDir, repo.Name, idx); err != nil {
				fmt.Printf("  [well] Extract failed: %v\n", err)
			}
		}
	}

	// Save index
	data, _ := json.MarshalIndent(idx, "", "  ")
	os.WriteFile(idxPath, data, 0600)

	fmt.Printf("  [well] Synced %d blueprint(s) to %s\n", len(idx.Blueprints), targetDir)
	return idx, nil
}

// ── GitHub API helpers ──────────────────────────────────────────────────

type releaseAsset struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	URL  string `json:"browser_download_url"`
}

func fetchReleaseAssets(releasesURL string) ([]releaseAsset, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, _ := http.NewRequest("GET", releasesURL, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "sxsc-well/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("GitHub API: %s — %s", resp.Status, string(body))
	}

	var release struct {
		Assets []releaseAsset `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}
	return release.Assets, nil
}

func downloadAndExtract(url, targetDir, repoName string, idx *Index) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Download to temp file
	tmpFile, err := os.CreateTemp("", "sxsc-blueprint-*.zip")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	_, err = io.CopyN(tmpFile, resp.Body, 100<<20) // 100MB limit
	tmpFile.Close()
	if err != nil && err != io.EOF {
		return err
	}

	// Extract
	reader, err := zip.OpenReader(tmpFile.Name())
	if err != nil {
		return err
	}
	defer reader.Close()

	for _, f := range reader.File {
		if !strings.HasSuffix(f.Name, ".yaml") && !strings.HasSuffix(f.Name, ".yml") {
			continue
		}
		destPath := filepath.Join(targetDir, filepath.Base(f.Name))
		dest, err := os.Create(destPath)
		if err != nil {
			continue
		}
		src, _ := f.Open()
		io.Copy(dest, src) //nolint:errcheck
		src.Close()
		dest.Close()

		// Quick parse for metadata (id + title)
		info := peekBlueprint(destPath)
		info.Source = repoName
		info.File = destPath
		idx.Blueprints[info.ID] = info
	}

	return nil
}

// peekBlueprint reads just enough YAML to get the ID and title.
func peekBlueprint(path string) BlueprintInfo {
	data, err := os.ReadFile(path)
	if err != nil {
		return BlueprintInfo{ID: filepath.Base(path)}
	}
	info := BlueprintInfo{ID: filepath.Base(path)}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "id:") {
			info.ID = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
		}
		if strings.HasPrefix(line, "title:") {
			info.Title = strings.TrimSpace(strings.TrimPrefix(line, "title:"))
		}
		if strings.HasPrefix(line, "level:") {
			info.Level = strings.TrimSpace(strings.TrimPrefix(line, "level:"))
		}
		if strings.HasPrefix(line, "label:") {
			labels := strings.TrimSpace(strings.TrimPrefix(line, "label:"))
			labels = strings.Trim(labels, "[]")
			for _, l := range strings.Split(labels, ",") {
				l = strings.TrimSpace(l)
				if l != "" { info.Labels = append(info.Labels, l) }
			}
		}
	}
	return info
}

// ── Query ────────────────────────────────────────────────────────────────

// List returns all installed blueprints.
func (idx *Index) List() []BlueprintInfo {
	var list []BlueprintInfo
	for _, info := range idx.Blueprints {
		list = append(list, info)
	}
	return list
}

// Count returns the number of installed blueprints.
func (idx *Index) Count() int { return len(idx.Blueprints) }
