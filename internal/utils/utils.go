package utils

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"
)

var (
	httpClient     *http.Client
	httpClientOnce sync.Once
	userAgentValue string
)

// userAgentTransport wraps http.RoundTripper to inject User-Agent header
type userAgentTransport struct {
	base http.RoundTripper
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", userAgentValue)
	return t.base.RoundTrip(req)
}

func InitHTTPClient(timeout time.Duration, userAgent string) {
	userAgentValue = userAgent

	// Default resolver: Google DNS
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 10 * time.Second}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	httpClientOnce.Do(func() {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // needed for expired/mismatched certs on dangling domains
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     30 * time.Second,
			DisableKeepAlives:   false,
		}
		httpClient = &http.Client{
			Timeout: timeout,
			Transport: &userAgentTransport{
				base: transport,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		}
	})
}

// SetCustomResolver overrides the default DNS resolver with a custom one
func SetCustomResolver(resolver string) {
	// Ensure resolver has port
	if _, _, err := net.SplitHostPort(resolver); err != nil {
		resolver = net.JoinHostPort(resolver, "53")
	}
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 10 * time.Second}
			return d.DialContext(ctx, "udp", resolver)
		},
	}
}

func GetHTTPClient() *http.Client {
	return httpClient
}
