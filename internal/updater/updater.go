package updater

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/SentinelXofficial/sxvwb/internal/color"
	"github.com/SentinelXofficial/sxvwb/internal/version"
)

// FetchLatest queries the GitHub releases API and returns the latest
// published tag for the sxsc repo, e.g. "v1.2.0".
func FetchLatest() (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	url := "https://api.github.com/repos/" + version.Repo + "/releases/latest"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "sxsc/"+version.Current)
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

// Update checks the latest GitHub release and, if newer than the running
// binary, reinstalls sxsc via `go install` at the latest tag.
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
	if _, err := exec.LookPath("go"); err != nil {
		fmt.Println(color.RED + "  [ERR] go binary not found in PATH" + color.RST)
		os.Exit(1)
	}
	fmt.Printf(color.GRY+"  [INF] Updating sxsc to %s..."+color.RST+"\n", latest)
	cmd := exec.Command("go", "install", "github.com/"+version.Repo+"/cmd/sxsc@"+latest)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Println(color.RED + "  [ERR] Update failed: " + err.Error() + color.RST)
		os.Exit(1)
	}
	fmt.Printf(color.GRN+"  [OK] Updated to %s. Restart sxsc."+color.RST+"\n", latest)
}
