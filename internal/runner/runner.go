package runner

import (
	"encoding/json"
	"fmt"
	"os"
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
	config      *config.Config
	outputFile  *os.File
	mu          sync.Mutex // protects outputFile writes
}

func NewRunner(updateDB bool, filter, version string, concurrency int, cfg *config.Config) (*Runner, error) {
	if !cfg.Silent {
		gologger.Info().Msgf("Loading takeit fingerprints... (version: %s)", version)
	}

	detector, err := detect.NewDetector(updateDB, cfg)
	if err != nil {
		return nil, err
	}

	r := &Runner{
		detector:    detector,
		filter:      filter,
		version:     version,
		concurrency: concurrency,
		config:      cfg,
	}

	// Open output file if specified
	if cfg.Output != "" {
		f, err := os.Create(cfg.Output)
		if err != nil {
			return nil, fmt.Errorf("cannot create output file: %v", err)
		}
		r.outputFile = f
	}

	return r, nil
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

	if r.outputFile != nil {
		r.outputFile.Close()
	}
}

func (r *Runner) ProcessDomain(domain string) {
	result := r.detector.CheckSubdomain(domain)

	// JSON output mode
	if r.config.JSONOut {
		r.outputJSON(result)
		return
	}

	// Filter mode: only show potential takeovers
	if r.filter != "" && !result.Vulnerable {
		return
	}

	if !r.config.Silent {
		r.logResult(result)
	}

	if result.Vulnerable {
		msg := fmt.Sprintf("[VULNERABLE] %s -> %s [Service: %s]", result.Domain, result.CNAME, result.Service)
		if result.IsWildcard {
			msg += " [WILDCARD - verify manually]"
		}
		gologger.Warning().Msg(msg)
		r.writeOutput(msg)
	} else if r.filter == "" {
		if !r.config.Silent {
			gologger.Info().Msgf("[SAFE] %s -> %s", result.Domain, result.CNAME)
		}
	}
}

func (r *Runner) logResult(result detect.Result) {
	gologger.Info().Msgf("Checking: %s", result.Domain)
	if result.CNAME != result.Domain {
		gologger.Info().Msgf("  CNAME: %s", result.CNAME)
	}
	if len(result.CNAMEChain) > 1 {
		gologger.Debug().Msgf("  CNAME chain: %v", result.CNAMEChain)
	}
}

func (r *Runner) outputJSON(result detect.Result) {
	r.mu.Lock()
	defer r.mu.Unlock()

	data, err := json.Marshal(result)
	if err != nil {
		return
	}
	line := string(data)
	fmt.Println(line)

	if r.outputFile != nil {
		fmt.Fprintln(r.outputFile, line)
	}
}

func (r *Runner) writeOutput(line string) {
	if r.outputFile == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	fmt.Fprintln(r.outputFile, line)
}
