package config

type Config struct {
	Threads int `json:"threads"`
	Timeout int `json:"timeout"`
}

func DefaultConfig() *Config {
	return &Config{
		Threads: 10,
		Timeout: 10,
	}
}
