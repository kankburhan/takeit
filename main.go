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
	fmt.Printf("  -update        Update takeit version\n")
	fmt.Printf("  -update-db     Update fingerprint database\n")
	fmt.Printf("  -t             Number of threads (default 10)\n")
	fmt.Printf("  -v             Show version\n")
	fmt.Printf("  -h             Show help\n")
	fmt.Printf("  -f             Filter output ( potential )\n\n")
}

func main() {
	updateDB := flag.Bool("update-db", false, "Update fingerprint database")
	updateTool := flag.Bool("update", false, "Update takeit version")
	threads := flag.Int("t", 10, "Number of threads")
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
				// Fallback to commit hash for dev builds
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
	if !*updateDB && (stat.Mode()&os.ModeCharDevice) != 0 && len(flag.Args()) == 0 {
		showHelp()
		os.Exit(0)
	}

	showBanner()
	gologger.Info().Msgf("Current takeit version %s", version)

	config := config.DefaultConfig()
	// NewRunner now expects (updateDB, filter, version, concurrency, config)
	runner, err := runner.NewRunner(*updateDB, *filterFlag, version, *threads, config)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s", err)
	}

	domains := make(chan string)
	go func() {
		defer close(domains)
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				domains <- scanner.Text()
			}
		} else if len(flag.Args()) > 0 {
			domains <- flag.Arg(0)
		}
	}()

	runner.Run(domains)
}
