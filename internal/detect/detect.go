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
	"github.com/schollz/progressbar/v3"
)

type Service struct {
	Service     string   `json:"service"`
	CNAME       []string `json:"cname"`
	NXDomain    bool     `json:"nxdomain"`
	HTTPStatus  int      `json:"http_status"`
	Status      string   `json:"status"`
	Vulnerable  bool     `json:"vulnerable"`
	Fingerprint string   `json:"fingerprint"`
}

// Result holds detailed information about a subdomain check
type Result struct {
	Domain      string   `json:"domain"`
	CNAME       string   `json:"cname"`
	CNAMEChain  []string `json:"cname_chain,omitempty"`
	Vulnerable  bool     `json:"vulnerable"`
	Service     string   `json:"service,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	IsWildcard  bool     `json:"is_wildcard,omitempty"`
	HTTPStatus  int      `json:"http_status,omitempty"`
	Error       string   `json:"error,omitempty"`
}

type Detector struct {
	services []Service
	config   *config.Config
}

const (
	fingerprintsURL   = "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json"
	localFingerprints = "fingerprints.json"
	configDir         = ".config/takeit"
	maxBodySize       = 1 << 20 // 1MB limit for HTTP body
	maxCNAMEDepth     = 10      // max CNAME chain depth
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

	if config.Resolver != "" {
		utils.SetCustomResolver(config.Resolver)
	}

	services, err := loadFingerprints(cachePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load fingerprints: %v", err)
	}

	gologger.Info().Msgf("Loaded %d fingerprints", len(services))

	return &Detector{services: services, config: config}, nil
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

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()

	bar := progressbar.DefaultBytes(
		resp.ContentLength,
		"downloading",
	)

	_, err = io.Copy(io.MultiWriter(out, bar), resp.Body)
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

// resolveCNAMEChain follows the full CNAME chain for a domain
func resolveCNAMEChain(domain string) []string {
	var chain []string
	seen := make(map[string]bool)
	current := domain

	for i := 0; i < maxCNAMEDepth; i++ {
		cname, err := net.LookupCNAME(current)
		if err != nil {
			break
		}
		cname = strings.TrimSuffix(cname, ".")
		if cname == current || seen[cname] {
			break // avoid loops
		}
		seen[cname] = true
		chain = append(chain, cname)
		current = cname
	}
	return chain
}

// detectWildcard checks if the parent domain has wildcard DNS
func detectWildcard(domain string) bool {
	parts := strings.SplitN(domain, ".", 2)
	if len(parts) < 2 {
		return false
	}
	parentDomain := parts[1]

	// Query a random non-existent subdomain
	randomSub := fmt.Sprintf("takeit-wildcard-test-7f3a2b.%s", parentDomain)
	addrs, err := net.LookupHost(randomSub)
	if err != nil {
		return false
	}
	return len(addrs) > 0
}

// CheckSubdomain checks a domain for potential subdomain takeover
func (d *Detector) CheckSubdomain(domain string) Result {
	result := Result{Domain: domain}

	// Resolve full CNAME chain
	chain := resolveCNAMEChain(domain)
	if len(chain) > 0 {
		result.CNAME = chain[len(chain)-1]
		result.CNAMEChain = chain
	} else {
		// No CNAME found - could still check for dangling A records
		result.CNAME = domain
	}

	// Check for wildcard DNS (potential false positive source)
	if detectWildcard(domain) {
		result.IsWildcard = true
		gologger.Debug().Msgf("Wildcard DNS detected for parent of %s", domain)
	}

	var (
		nxDomainChecked bool
		nxDomainResult  bool
		httpChecked     bool
		httpStatus      int
		httpBody        string
	)

	for _, service := range d.services {
		// Check CNAME patterns against entire chain
		cnameMatched := false
		for _, pattern := range service.CNAME {
			patternLower := strings.ToLower(pattern)
			// Check final CNAME
			if strings.HasSuffix(strings.ToLower(result.CNAME), patternLower) {
				cnameMatched = true
				break
			}
			// Also check intermediate CNAME chain entries
			for _, c := range chain {
				if strings.HasSuffix(strings.ToLower(c), patternLower) {
					cnameMatched = true
					break
				}
			}
			if cnameMatched {
				break
			}
		}
		if !cnameMatched {
			continue
		}

		// Check NXDOMAIN condition using net.LookupHost (correct method)
		if service.NXDomain {
			if !nxDomainChecked {
				nx, err := isNXDomain(result.CNAME)
				gologger.Debug().Msgf("NXDOMAIN check for %s (CNAME: %s): %v (err: %v)", domain, result.CNAME, nx, err)
				if err != nil {
					// Retry once on transient DNS errors
					time.Sleep(500 * time.Millisecond)
					nx, err = isNXDomain(result.CNAME)
					if err != nil {
						continue
					}
				}
				nxDomainResult = nx
				nxDomainChecked = true
			}
			if !nxDomainResult {
				continue
			}
		}

		// Check HTTP status code and fingerprint if required
		if service.HTTPStatus != 0 || service.Fingerprint != "" {
			if !httpChecked {
				status, body, err := d.fetchHTTPStatus(domain)
				if err != nil {
					// Retry once
					time.Sleep(500 * time.Millisecond)
					status, body, err = d.fetchHTTPStatus(domain)
					if err != nil {
						continue
					}
				}
				httpStatus = status
				httpBody = body
				httpChecked = true
			}

			if service.HTTPStatus != 0 && httpStatus != service.HTTPStatus {
				continue
			}

			if service.Fingerprint != "" && !strings.Contains(
				strings.ToLower(httpBody),
				strings.ToLower(service.Fingerprint),
			) {
				continue
			}
		}

		// All conditions met
		if service.Vulnerable {
			result.Vulnerable = true
			result.Service = service.Service
			result.Fingerprint = service.Fingerprint
			result.HTTPStatus = httpStatus
			return result
		}
	}

	return result
}

// fetchHTTPStatus fetches HTTP status and body (limited to maxBodySize)
func (d *Detector) fetchHTTPStatus(domain string) (int, string, error) {
	client := utils.GetHTTPClient()

	urls := []string{
		fmt.Sprintf("https://%s", domain),
		fmt.Sprintf("http://%s", domain),
	}

	for _, url := range urls {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		// Read body with size limit to prevent OOM
		bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
		resp.Body.Close() // close immediately, not defer in loop
		if readErr != nil {
			return resp.StatusCode, "", nil
		}
		return resp.StatusCode, string(bodyBytes), nil
	}
	return 0, "", fmt.Errorf("all HTTP(S) requests failed for %s", domain)
}

// isNXDomain checks if a domain resolves to NXDOMAIN using net.LookupHost
func isNXDomain(domain string) (bool, error) {
	_, err := net.LookupHost(domain)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return true, nil
		}
		return false, err
	}
	return false, nil
}
