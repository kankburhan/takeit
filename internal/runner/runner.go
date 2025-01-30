package runner

import (
	"github.com/kankburhan/takeit/internal/detect"
	"github.com/projectdiscovery/gologger"
)

type Runner struct {
	detector *detect.Detector
	filter   string
	version  string
}

func NewRunner(update bool, filter, version string) (*Runner, error) {
	gologger.Info().Msgf("Loading takeit fingerprints... (version: %s)", version)
	detector, err := detect.NewDetector(update)
	if err != nil {
		return nil, err
	}
	return &Runner{detector: detector, filter: filter, version: version}, nil
}

func (r *Runner) ProcessDomain(domain string) {
	vulnerable, err, cname := r.detector.CheckSubdomain(domain)
	if err != nil && r.filter == "" {
		gologger.Info().Msgf("Checking domain: %s", domain)
		gologger.Info().Msgf("Resolved CNAME for %s: %s", domain, cname)
		gologger.Error().Msgf("Error checking %s: %s", domain, err)
		return
	}
	if vulnerable {
		if r.filter == "potential" {
			gologger.Info().Msgf("Checking domain: %s", domain)
			gologger.Info().Msgf("Resolved CNAME for %s: %s", domain, cname)
			gologger.Warning().Msgf("Potential subdomain takeover detected: %s", domain)
		}
	} else {
		if r.filter == "" {
			gologger.Info().Msgf("Checking domain: %s", domain)
			gologger.Info().Msgf("Resolved CNAME for %s: %s", domain, cname)
			gologger.Info().Msgf("No takeover detected for: %s", domain)
		}
	}
}
