package utils

import (
	"net/http"
	"time"
)

var client = &http.Client{Timeout: 10 * time.Second}

func HTTPGet(url string) (*http.Response, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
