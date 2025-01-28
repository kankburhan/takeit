// main.go
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"

	"github.com/kankburhan/takeit/internal/runner"
	"github.com/projectdiscovery/gologger"
)

const version = "v0.1.2"

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
	fmt.Printf("  -update        Update fingerprint database\n")
	fmt.Printf("  -v             Show version\n")
	fmt.Printf("  -h             Show help\n\n")
}

func main() {
	update := flag.Bool("update", false, "Update fingerprint database")
	versionFlag := flag.Bool("v", false, "Show version")
	helpFlag := flag.Bool("h", false, "Show help")
	flag.Parse()

	if *helpFlag {
		showHelp()
		os.Exit(0)
	}

	if *versionFlag {
		fmt.Printf("takeit version %s\n", version)
		os.Exit(0)
	}

	stat, _ := os.Stdin.Stat()
	if !*update && (stat.Mode()&os.ModeCharDevice) != 0 && len(flag.Args()) == 0 {
		showHelp()
		os.Exit(0)
	}

	showBanner()
	gologger.Info().Msgf("Current takeit version %s", version)

	runner, err := runner.NewRunner(*update)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s", err)
	}

	if (stat.Mode() & os.ModeCharDevice) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			runner.ProcessDomain(scanner.Text())
		}
	} else if len(flag.Args()) > 0 {
		runner.ProcessDomain(flag.Arg(0))
	}
}
