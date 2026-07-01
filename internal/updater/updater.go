package updater

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/SentinelXofficial/sxvwb/internal/color"
	"github.com/SentinelXofficial/sxvwb/internal/version"
)

// FetchLatest queries the GitHub releases API and returns the latest tag.
func FetchLatest() (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	url := "https://api.github.com/repos/" + version.Repo + "/releases/latest"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "sxvwb/"+version.Current)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github api error: %s", resp.Status)
	}

	var data struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}
	if data.TagName == "" {
		return "", fmt.Errorf("latest release tag not found")
	}
	return data.TagName, nil
}

// Update downloads the latest binary from the GitHub release and replaces the
// current binary. Closed-source — no go install.
func Update() {
	latest, err := FetchLatest()
	if err != nil {
		fmt.Println(color.RED + "  [ERR] " + err.Error() + color.RST)
		os.Exit(1)
	}
	if latest == version.Current {
		fmt.Printf(color.GRY+"  [INF] Already on latest version: "+color.BOLD+"%s"+color.RST+"\n", version.Current)
		return
	}

	fmt.Printf(color.GRY+"  [INF] Updating sxvwb to %s..."+color.RST+"\n", latest)

	// Determine the asset name for this platform
	assetName := "sxvwb-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		assetName += ".exe"
	}

	// Build the download URL
	downloadURL := fmt.Sprintf(
		"https://github.com/%s/releases/download/%s/%s",
		version.Repo, latest, assetName,
	)

	// Download the new binary
	resp, err := http.Get(downloadURL)
	if err != nil {
		fmt.Println(color.RED + "  [ERR] Download failed: " + err.Error() + color.RST)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf(color.RED+"  [ERR] Binary %s not found in release %s (HTTP %d)"+color.RST+"\n",
			assetName, latest, resp.StatusCode)
		os.Exit(1)
	}

	// Write to a temp file first, then atomically replace
	exe, err := os.Executable()
	if err != nil {
		fmt.Println(color.RED + "  [ERR] Cannot find current binary: " + err.Error() + color.RST)
		os.Exit(1)
	}

	tmpPath := exe + ".new"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		fmt.Println(color.RED + "  [ERR] Cannot create temp file: " + err.Error() + color.RST)
		os.Exit(1)
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmpPath)
		fmt.Println(color.RED + "  [ERR] Write failed: " + err.Error() + color.RST)
		os.Exit(1)
	}
	f.Close()

	// Atomic replace
	if err := os.Rename(tmpPath, exe); err != nil {
		// Fallback: try cp + rm
		cpCmd := exec.Command("cp", tmpPath, exe)
		if err := cpCmd.Run(); err != nil {
			os.Remove(tmpPath)
			fmt.Println(color.RED+"  [ERR] Replace failed: "+err.Error()+color.RST+
				"\n  Download the new binary manually from: "+downloadURL+color.RST)
			os.Exit(1)
		}
		os.Remove(tmpPath)
	}

	fmt.Printf(color.GRN+"  [OK] Updated to %s. Restart sxvwb."+color.RST+"\n", latest)

	// On Linux/macOS: attempt a graceful self-restart via exec
	if runtime.GOOS != "windows" {
		_ = os.Chmod(exe, 0755)
	}
}

// fileExists is a helper kept for potential future use.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ensureDir creates a directory if it doesn't exist.
func ensureDir(path string) error {
	return os.MkdirAll(filepath.Dir(path), 0755)
}
