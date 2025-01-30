package config

type Config struct {
	Threads   int    `json:"threads"`
	Timeout   int    `json:"timeout"`
	UserAgent string `json:"user_agent"`
}

func DefaultConfig() *Config {
	return &Config{
		Threads:   10,
		Timeout:   10,
		UserAgent: "takeit/1.0",
	}
}
