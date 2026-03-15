package config

type Config struct {
	Threads   int    `json:"threads"`
	Timeout   int    `json:"timeout"`
	UserAgent string `json:"user_agent"`
	Resolver  string `json:"resolver"`
	Silent    bool   `json:"silent"`
	JSONOut   bool   `json:"json_output"`
	Output    string `json:"output"`
}

func DefaultConfig() *Config {
	return &Config{
		Threads:   10,
		Timeout:   10,
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	}
}
