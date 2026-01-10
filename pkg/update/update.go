package update

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/projectdiscovery/gologger"
)

const (
	repoOwner = "kankburhan"
	repoName  = "takeit"
)

type Release struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func CheckForUpdate(currentVersion string) (*Release, error) {
	if currentVersion == "dev" {
		return nil, nil
	}

	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", repoOwner, repoName)
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status: %s", resp.Status)
	}

	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}

	// Simple version comparison (assumes format vX.Y.Z)
	if release.TagName != currentVersion && release.TagName != "v"+currentVersion {
		return &release, nil
	}

	return nil, nil
}

func SelfUpdate(currentVersion string) error {
	gologger.Info().Msgf("Checking for updates (current: %s)...", currentVersion)
	release, err := CheckForUpdate(currentVersion)
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}
	if release == nil {
		gologger.Info().Msg("You are using the latest version.")
		return nil
	}

	gologger.Info().Msgf("New version found: %s", release.TagName)
	gologger.Info().Msg("Updating...")

	cmd := exec.Command("go", "install", fmt.Sprintf("github.com/%s/%s@%s", repoOwner, repoName, release.TagName))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("update failed: %w", err)
	}

	gologger.Info().Msg("Update successfully! Please restart the tool.")
	return nil
}

func ShowUpdateMessage(latestVersion string) {
	fmt.Printf("\n\n")
	gologger.Warning().Msgf("New version %s is available!", latestVersion)
	gologger.Info().Msg("Please update using: takeit -update")
	fmt.Printf("\n\n")
}
