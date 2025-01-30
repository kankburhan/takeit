package utils

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"
)

var (
	httpClient     *http.Client
	httpClientOnce sync.Once
)

func InitHTTPClient(timeout time.Duration, userAgent string) {
	// force to use DNS resolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 10 * time.Second}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}
	httpClientOnce.Do(func() {
		httpClient = &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{},
		}
	})
}

func GetHTTPClient() *http.Client {
	return httpClient
}
