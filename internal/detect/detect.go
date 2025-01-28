// internal/detect/detect.go
package detect

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/gologger"
)

type Service struct {
	Service      string   `json:"service"`
	CNAME        []string `json:"cname"`
	NXDomain     bool     `json:"nxdomain"`
	HTTPStatus   int      `json:"http_status"`
	ResponseBody string   `json:"response_body"`
}

type Detector struct {
	services []Service
}

const (
	fingerprintsURL   = "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json"
	localFingerprints = "fingerprints.json"
	configDir         = ".config/takeit"
)

func NewDetector(update bool) (*Detector, error) {
	if err := createConfigDir(); err != nil {
		return nil, err
	}

	cachePath := filepath.Join(getConfigDir(), localFingerprints)

	if update || !fileExists(cachePath) {
		gologger.Info().Msg("Downloading latest fingerprints for takeit...")
		if err := downloadFingerprints(cachePath); err != nil {
			if !fileExists(cachePath) {
				return nil, fmt.Errorf("could not download fingerprints and no local cache exists")
			}
			gologger.Error().Msgf("Using cached fingerprints due to download error: %s", err)
		}
	}

	services, err := loadFingerprints(cachePath)
	if err != nil {
		return nil, fmt.Errorf("could not load fingerprints: %s", err)
	}

	return &Detector{services: services}, nil
}

func createConfigDir() error {
	configPath := getConfigDir()
	return os.MkdirAll(configPath, 0755)
}

func getConfigDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, configDir)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func downloadFingerprints(path string) error {
	resp, err := http.Get(fingerprintsURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func loadFingerprints(path string) ([]Service, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var services []Service
	err = json.NewDecoder(file).Decode(&services)
	return services, err
}

func (d *Detector) CheckSubdomain(domain string) (bool, error) {
	cname, err := net.LookupCNAME(domain)
	if err != nil {
		return false, fmt.Errorf("could not resolve CNAME for %s: %s", domain, err)
	}
	cname = strings.TrimSuffix(cname, ".")

	gologger.Info().Msgf("Resolved CNAME for %s: %s", domain, cname)

	for _, service := range d.services {
		for _, pattern := range service.CNAME {
			if strings.Contains(cname, pattern) {
				gologger.Info().Msgf("Potential match with %s service", service.Service)
				return true, nil
			}
		}
	}
	return false, nil
}
