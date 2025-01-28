package runner

import (
	"github.com/kankburhan/takeit/internal/detect"
	"github.com/projectdiscovery/gologger"
)

type Runner struct {
	detector *detect.Detector
}

func NewRunner(update bool) (*Runner, error) {
	gologger.Info().Msg("Loading takeit fingerprints...")
	detector, err := detect.NewDetector(update)
	if err != nil {
		return nil, err
	}
	return &Runner{detector: detector}, nil
}

func (r *Runner) ProcessDomain(domain string) {
	gologger.Info().Msgf("Checking domain: %s", domain)
	vulnerable, err := r.detector.CheckSubdomain(domain)
	if err != nil {
		gologger.Error().Msgf("Error checking %s: %s", domain, err)
		return
	}
	if vulnerable {
		gologger.Warning().Msgf("Potential subdomain takeover detected: %s", domain)
	} else {
		gologger.Info().Msgf("No takeover detected for: %s", domain)
	}
}
