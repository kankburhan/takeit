// main.go
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/kankburhan/takeit/internal/runner"
	"github.com/kankburhan/takeit/pkg/config"
	"github.com/kankburhan/takeit/pkg/update"
	"github.com/projectdiscovery/gologger"
)

var version = "dev" // default version

func showBanner() {
	fmt.Print(`
	_____     _       _____ _
	|_   _|   | |     |_   _| |
	  | | __ _| | _____ | | | |_
	  | |/ _' | |/ / _ \| | | __|
	  | | (_| |   <  __/| |_| |_
	  \_/\__,_|_|\_\___\___/ \__|
			by kankburhan

`)
}

func showHelp() {
	showBanner()
	fmt.Printf("Usage:\n")
	fmt.Printf("  takeit [flags] <domain>\n")
	fmt.Printf("  cat domains.txt | takeit [flags]\n\n")
	fmt.Printf("Flags:\n")
	fmt.Printf("  -l  string     File containing list of domains\n")
	fmt.Printf("  -t  int        Number of threads (default 10)\n")
	fmt.Printf("  -timeout int   HTTP timeout in seconds (default 10)\n")
	fmt.Printf("  -r  string     Custom DNS resolver (e.g., 1.1.1.1 or 1.1.1.1:53)\n")
	fmt.Printf("  -o  string     Output file for results\n")
	fmt.Printf("  -f  string     Filter output (e.g., potential)\n")
	fmt.Printf("  -json          Output results as JSON lines\n")
	fmt.Printf("  -silent        Show only vulnerable results\n")
	fmt.Printf("  -update        Update takeit version\n")
	fmt.Printf("  -update-db     Update fingerprint database\n")
	fmt.Printf("  -v             Show version\n")
	fmt.Printf("  -h             Show help\n\n")
	fmt.Printf("Examples:\n")
	fmt.Printf("  takeit example.com\n")
	fmt.Printf("  takeit -l domains.txt -t 20 -o results.txt\n")
	fmt.Printf("  cat subs.txt | takeit -json -silent\n")
	fmt.Printf("  takeit -l domains.txt -r 1.1.1.1 -json\n\n")
}

func main() {
	updateDB := flag.Bool("update-db", false, "Update fingerprint database")
	updateTool := flag.Bool("update", false, "Update takeit version")
	threads := flag.Int("t", 10, "Number of threads")
	timeout := flag.Int("timeout", 10, "HTTP timeout in seconds")
	resolver := flag.String("r", "", "Custom DNS resolver (e.g., 1.1.1.1)")
	listFile := flag.String("l", "", "File containing list of domains")
	outputFile := flag.String("o", "", "Output file for results")
	jsonOutput := flag.Bool("json", false, "Output results as JSON lines")
	silentMode := flag.Bool("silent", false, "Show only vulnerable results")
	versionFlag := flag.Bool("v", false, "Show version")
	helpFlag := flag.Bool("h", false, "Show help")
	filterFlag := flag.String("f", "", "Filter output (e.g., potential)")
	flag.Parse()

	// Get version from environment variable
	if v := os.Getenv("TAKEIT_VERSION"); v != "" {
		version = v
	}

	// Try to get version from build info if it's still dev
	if version == "dev" {
		if info, ok := debug.ReadBuildInfo(); ok {
			if info.Main.Version != "(devel)" {
				version = info.Main.Version
			} else {
				for _, setting := range info.Settings {
					if setting.Key == "vcs.revision" && len(setting.Value) >= 7 {
						version = "dev-" + setting.Value[:7]
						break
					}
				}
			}
		}
	}

	// Handle tool update
	if *updateTool {
		if err := update.SelfUpdate(version); err != nil {
			gologger.Fatal().Msgf("Update failed: %s", err)
		}
		os.Exit(0)
	}

	go func() {
		if release, err := update.CheckForUpdate(version); err == nil && release != nil {
			update.ShowUpdateMessage(release.TagName)
		}
	}()

	if *helpFlag {
		showHelp()
		os.Exit(0)
	}

	if *versionFlag {
		fmt.Printf("takeit version %s\n", version)
		os.Exit(0)
	}

	stat, _ := os.Stdin.Stat()
	hasStdin := (stat.Mode() & os.ModeCharDevice) == 0
	hasListFile := *listFile != ""
	hasArgs := len(flag.Args()) > 0

	if !*updateDB && !hasStdin && !hasListFile && !hasArgs {
		showHelp()
		os.Exit(0)
	}

	if !*silentMode {
		showBanner()
		gologger.Info().Msgf("Current takeit version %s", version)
	}

	cfg := config.DefaultConfig()
	cfg.Threads = *threads
	cfg.Timeout = *timeout
	cfg.Resolver = *resolver
	cfg.Silent = *silentMode
	cfg.JSONOut = *jsonOutput
	cfg.Output = *outputFile

	r, err := runner.NewRunner(*updateDB, *filterFlag, version, *threads, cfg)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s", err)
	}

	domains := make(chan string)
	go func() {
		defer close(domains)
		seen := make(map[string]bool)

		addDomain := func(d string) {
			if d != "" && !seen[d] {
				seen[d] = true
				domains <- d
			}
		}

		// Read from stdin
		if hasStdin {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				addDomain(scanner.Text())
			}
		}

		// Read from file
		if hasListFile {
			f, err := os.Open(*listFile)
			if err != nil {
				gologger.Fatal().Msgf("Cannot open file %s: %s", *listFile, err)
			}
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				addDomain(scanner.Text())
			}
		}

		// Read from args
		for _, arg := range flag.Args() {
			addDomain(arg)
		}
	}()

	r.Run(domains)
}
