// Package cerner provides a minimal Oracle Health Millennium FHIR client.
package cerner

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultScope   = "system/Patient.read"
	defaultTimeout = 15 * time.Second
)

// Config contains tenant-specific settings. Secrets are never hardcoded.
type Config struct {
	AuthMethod     string
	ClientID       string
	ClientSecret   string
	TokenURL       string
	FHIRBaseURL    string
	PrivateKeyPath string
	KeyID          string
	Scopes         string
}

// Client supports dependency injection for deterministic tests.
type Client struct {
	Config     Config
	HTTPClient *http.Client
	now        func() time.Time
	rand       func([]byte) (int, error)
}

// NewClientFromEnv reads configuration and creates a client with a bounded timeout.
func NewClientFromEnv() (*Client, error) {
	timeout := defaultTimeout
	if value := strings.TrimSpace(os.Getenv("CERNER_HTTP_TIMEOUT")); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil || parsed <= 0 {
			return nil, fmt.Errorf("CERNER_HTTP_TIMEOUT must be a positive Go duration: %q", value)
		}
		timeout = parsed
	}

	scopes := strings.TrimSpace(os.Getenv("CERNER_SCOPES"))
	if scopes == "" {
		scopes = defaultScope
	}
	return NewClient(Config{
		AuthMethod:     strings.TrimSpace(os.Getenv("CERNER_AUTH_METHOD")),
		ClientID:       strings.TrimSpace(os.Getenv("CERNER_CLIENT_ID")),
		ClientSecret:   strings.TrimSpace(os.Getenv("CERNER_CLIENT_SECRET")),
		TokenURL:       strings.TrimSpace(os.Getenv("CERNER_TOKEN_URL")),
		FHIRBaseURL:    strings.TrimSpace(os.Getenv("CERNER_FHIR_BASE_URL")),
		PrivateKeyPath: strings.TrimSpace(os.Getenv("CERNER_PRIVATE_KEY_PATH")),
		KeyID:          strings.TrimSpace(os.Getenv("CERNER_KEY_ID")),
		Scopes:         scopes,
	}, &http.Client{Timeout: timeout}), nil
}

// NewClient creates a configured client. Supplying nil uses a 15-second timeout.
func NewClient(config Config, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultTimeout}
	}
	return &Client{Config: config, HTTPClient: httpClient, now: time.Now}
}

func require(values map[string]string) error {
	for name, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("required configuration %s is empty", name)
		}
	}
	return nil
}

// HTTPError preserves a bounded response body without exposing request credentials.
type HTTPError struct {
	Operation  string
	StatusCode int
	Status     string
	Body       []byte
}

func (e *HTTPError) Error() string {
	detail := strings.TrimSpace(string(e.Body))
	if detail == "" {
		return fmt.Sprintf("%s failed: %s", e.Operation, e.Status)
	}
	return fmt.Sprintf("%s failed: %s: %s", e.Operation, e.Status, detail)
}
