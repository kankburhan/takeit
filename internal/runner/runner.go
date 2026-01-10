package runner

import (
	"sync"

	"github.com/kankburhan/takeit/internal/detect"
	"github.com/kankburhan/takeit/pkg/config"
	"github.com/projectdiscovery/gologger"
)

type Runner struct {
	detector    *detect.Detector
	filter      string
	version     string
	concurrency int
}

func NewRunner(updateDB bool, filter, version string, concurrency int, config *config.Config) (*Runner, error) {
	gologger.Info().Msgf("Loading takeit fingerprints... (version: %s)", version)
	detector, err := detect.NewDetector(updateDB, config)
	if err != nil {
		return nil, err
	}
	return &Runner{detector: detector, filter: filter, version: version, concurrency: concurrency}, nil
}

func (r *Runner) Run(domains <-chan string) {
	var wg sync.WaitGroup
	for i := 0; i < r.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range domains {
				r.ProcessDomain(domain)
			}
		}()
	}
	wg.Wait()
}

func (r *Runner) ProcessDomain(domain string) {
	vulnerable, cname, err := r.detector.CheckSubdomain(domain)

	if err != nil {
		if r.filter == "" {
			r.logDomainDetails(domain, cname)
			gologger.Error().Msgf("Error checking %s: %s", domain, err)
		}
		return
	}

	// Only show details for vulnerable domains or when no filter is applied
	if vulnerable || r.filter == "" {
		r.logDomainDetails(domain, cname)
	}

	if vulnerable {
		gologger.Warning().Msgf("Potential subdomain takeover detected: %s", domain)
	} else if r.filter == "" {
		gologger.Info().Msgf("No takeover detected for: %s", domain)
	}
}

func (r *Runner) logDomainDetails(domain, cname string) {
	gologger.Info().Msgf("Checking domain: %s", domain)
	gologger.Info().Msgf("Resolved CNAME for %s: %s", domain, cname)
}
