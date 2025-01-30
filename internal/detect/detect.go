package detect

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kankburhan/takeit/internal/utils"
	"github.com/kankburhan/takeit/pkg/config"
	"github.com/projectdiscovery/gologger"
)

type Service struct {
	Service    string   `json:"service"`
	CNAME      []string `json:"cname"`
	NXDomain   bool     `json:"nxdomain"`
	HTTPStatus int      `json:"http_status"` // 0 means no HTTP check required
	Status     string   `json:"status"`
	Vulnerable bool     `json:"vulnerable"`
}

type Detector struct {
	services []Service
}

const (
	fingerprintsURL   = "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json"
	localFingerprints = "fingerprints.json"
	configDir         = ".config/takeit"
)

func NewDetector(update bool, config *config.Config) (*Detector, error) {
	if err := createConfigDir(); err != nil {
		return nil, err
	}

	cachePath := filepath.Join(getConfigDir(), localFingerprints)

	if update || !fileExists(cachePath) {
		gologger.Info().Msg("Downloading latest fingerprints...")
		if err := downloadFingerprints(cachePath); err != nil {
			if !fileExists(cachePath) {
				return nil, fmt.Errorf("download failed and no local cache found: %v", err)
			}
			gologger.Error().Msgf("Using cached fingerprints: %v", err)
		}
	}

	utils.InitHTTPClient(time.Duration(config.Timeout)*time.Second, config.UserAgent)

	services, err := loadFingerprints(cachePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load fingerprints: %v", err)
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

func (d *Detector) CheckSubdomain(domain string) (bool, string, error) {
	cname, err := net.LookupCNAME(domain)
	if err != nil {
		return false, "", fmt.Errorf("CNAME lookup failed for %s: %v", domain, err)
	}
	cname = strings.TrimSuffix(cname, ".")

	var (
		nxDomainChecked bool
		nxDomainResult  bool
		httpChecked     bool
		httpStatus      int
	)

	for _, service := range d.services {
		// Check CNAME patterns
		cnameMatched := false
		for _, pattern := range service.CNAME {
			if strings.HasSuffix(cname, pattern) {
				cnameMatched = true
				break
			}
		}
		if !cnameMatched {
			continue
		}

		// Check NXDOMAIN condition
		if service.NXDomain {
			if !nxDomainChecked {
				nx, err := isNXDomain(domain)
				gologger.Debug().Msgf("NXDOMAIN result for %s: %v (error: %v)", domain, nx, err)

				if err != nil {
					continue
				}
				nxDomainResult = nx
				nxDomainChecked = true
			}
			if !nxDomainResult {
				continue
			}
		}

		// Check HTTP status code if required
		if service.HTTPStatus != 0 {
			if !httpChecked {
				status, err := fetchHTTPStatus(domain)
				if err != nil {
					continue
				}
				httpStatus = status
				httpChecked = true
			}

			if httpStatus != service.HTTPStatus {
				continue
			}
		}

		// If all conditions are met, check vulnerability
		if service.Vulnerable {
			return true, cname, nil
		}
	}

	return false, cname, nil
}

// Simplified HTTP check (status code only)
func fetchHTTPStatus(domain string) (int, error) {
	client := utils.GetHTTPClient()

	// Try both HTTP and HTTPS
	urls := []string{fmt.Sprintf("http://%s", domain), fmt.Sprintf("https://%s", domain)}
	for _, url := range urls {
		resp, err := client.Get(url)
		if err == nil {
			defer resp.Body.Close()
			return resp.StatusCode, nil
		}
	}
	return 0, fmt.Errorf("all HTTP(S) requests failed")
}

func isNXDomain(domain string) (bool, error) {
	_, err := net.LookupCNAME(domain)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return true, nil
		}
		return false, err
	}
	return false, nil
}
