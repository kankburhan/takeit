# TakeIt

TakeIt is a blazing-fast subdomain takeover detection tool. With its intuitive CLI and updatable fingerprint database, TakeIt helps security professionals identify misconfigured subdomains that could be exploited.

## Key Features

- **Subdomain Takeover Detection**: Scans for vulnerabilities in DNS misconfigurations.
- **Fast and Lightweight**: Designed for performance and simplicity.
- **Updatable Fingerprint Database**: Keep your detection capabilities up-to-date.
- **Easy-to-Use CLI**: Minimal commands for maximum output.

## Installation

### Prebuilt Binaries
Download the latest release from the [Releases](https://github.com/kankburhan/takeit/releases) page.

### Go Install
You can install TakeIt directly using `go install`:
```bash
go install github.com/kankburhan/takeit@latest
```

### Build from Source

Requirements:
- Go 1.16+

Steps:
```bash
git clone https://github.com/kankburhan/takeit.git
cd takeit
go build -o takeit
```

## Usage

```text
        _____     _       _____ _   
        |_   _|   | |     |_   _| |  
          | | __ _| | _____ | | | |_ 
          | |/ _' | |/ / _ \| | | __|
          | | (_| |   <  __/| |_| |_ 
          \_/\__,_|_|\_\___\___/ \__|
                        by kankburhan
Usage:
  takeit [flags] <domain>
  cat domains.txt | takeit [flags]

Flags:
  -update        Update fingerprint database
  -v             Show version
  -h             Show help
  -f             Filter output ( potential )
```

### Examples

- Scan a single domain:
  ```bash
  ./takeit example.com
  ```

- Scan multiple domains from a file:
  ```bash
  cat domains.txt | ./takeit
  ```

- Update the fingerprint database:
  ```bash
  ./takeit -update
  ```

- Show only potential matches:
  ```bash
  ./takeit -f potential example.com
  ```

## Contributions

Contributions are welcome! Submit issues or pull requests to enhance the tool.

## License

TakeIt is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for educational and authorized security testing purposes only. Unauthorized use is strictly prohibited.
