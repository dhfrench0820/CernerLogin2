package cerner

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuthenticateConstructsAndSignsAssertion(t *testing.T) {
	privateKey, keyPath := testPrivateKey(t, false)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q", got)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if got := r.Form.Get("grant_type"); got != "client_credentials" {
			t.Errorf("grant_type = %q", got)
		}
		if got := r.Form.Get("scope"); got != "system/Patient.read" {
			t.Errorf("scope = %q", got)
		}
		if got := r.Form.Get("client_assertion_type"); got != assertionType {
			t.Errorf("client_assertion_type = %q", got)
		}
		assertion := r.Form.Get("client_assertion")
		parts := strings.Split(assertion, ".")
		if len(parts) != 3 {
			t.Fatalf("JWT has %d parts", len(parts))
		}
		var header map[string]any
		decodeJWTPart(t, parts[0], &header)
		if header["alg"] != "RS384" || header["kid"] != "test-key" {
			t.Errorf("unexpected JWT header: %#v", header)
		}
		var claims map[string]any
		decodeJWTPart(t, parts[1], &claims)
		if claims["iss"] != "test-client" || claims["sub"] != "test-client" || claims["aud"] != server.URL {
			t.Errorf("unexpected JWT claims: %#v", claims)
		}
		if claims["jti"] == "" {
			t.Error("jti is empty")
		}
		digest := sha512.Sum384([]byte(parts[0] + "." + parts[1]))
		signature, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatal(err)
		}
		if err := rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA384, digest[:], signature); err != nil {
			t.Errorf("JWT signature verification failed: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"sandbox-token","token_type":"Bearer"}`)
	}))
	defer server.Close()

	client := NewClient(Config{
		ClientID: "test-client", TokenURL: server.URL, PrivateKeyPath: keyPath,
		KeyID: "test-key", Scopes: "system/Patient.read",
	}, server.Client())
	client.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	token, err := client.Authenticate()
	if err != nil {
		t.Fatal(err)
	}
	if token != "sandbox-token" {
		t.Fatalf("token = %q", token)
	}
}

func TestAuthenticateReturnsCernerError(t *testing.T) {
	_, keyPath := testPrivateKey(t, true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"error":"invalid_client","error_description":"unknown kid"}`)
	}))
	defer server.Close()
	client := NewClient(Config{ClientID: "client", TokenURL: server.URL, PrivateKeyPath: keyPath, KeyID: "bad-kid", Scopes: defaultScope}, server.Client())

	_, err := client.Authenticate()
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("error = %v, want HTTPError 400", err)
	}
	if !strings.Contains(err.Error(), "invalid_client") || !strings.Contains(err.Error(), "unknown kid") {
		t.Fatalf("error does not preserve response body: %v", err)
	}
}

func TestAuthenticateWithClientSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID, secret, ok := r.BasicAuth()
		if !ok || clientID != "system-account" || secret != "test-secret" {
			t.Fatalf("unexpected Basic credentials")
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("client_assertion") != "" {
			t.Error("client-secret request contains a JWT assertion")
		}
		if got := r.Form.Get("scope"); got != "system/Patient.read" {
			t.Errorf("scope = %q", got)
		}
		io.WriteString(w, `{"access_token":"basic-token","token_type":"Bearer"}`)
	}))
	defer server.Close()

	client := NewClient(Config{
		AuthMethod: "client_secret", ClientID: "system-account", ClientSecret: "test-secret",
		TokenURL: server.URL, Scopes: defaultScope,
	}, server.Client())
	token, err := client.Authenticate()
	if err != nil {
		t.Fatal(err)
	}
	if token != "basic-token" {
		t.Fatalf("token = %q", token)
	}
}

func TestAuthenticateRejectsUnknownMethod(t *testing.T) {
	client := NewClient(Config{AuthMethod: "password", ClientID: "client", TokenURL: "https://example.test/token"}, nil)
	_, err := client.Authenticate()
	if err == nil || !strings.Contains(err.Error(), "jwt or client_secret") {
		t.Fatalf("error = %v", err)
	}
}

func TestAuthenticateRejectsMissingAccessToken(t *testing.T) {
	_, keyPath := testPrivateKey(t, false)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{}`)
	}))
	defer server.Close()
	client := NewClient(Config{ClientID: "client", TokenURL: server.URL, PrivateKeyPath: keyPath, KeyID: "key", Scopes: defaultScope}, server.Client())
	_, err := client.Authenticate()
	if err == nil || !strings.Contains(err.Error(), "access_token") {
		t.Fatalf("error = %v", err)
	}
}

func TestGetPatientReturnsFullRawJSON(t *testing.T) {
	want := []byte(`{"resourceType":"Patient","id":"123","extension":[{"url":"example","valueString":"preserved"}]}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/r4/Patient/123" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token-value" {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("Accept"); got != "application/fhir+json" {
			t.Errorf("Accept = %q", got)
		}
		w.Header().Set("Content-Type", "application/fhir+json")
		w.Write(want)
	}))
	defer server.Close()
	client := NewClient(Config{FHIRBaseURL: server.URL + "/r4/"}, server.Client())
	got, err := client.GetPatient("token-value", "123")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("body = %s, want %s", got, want)
	}
}

func TestGetPatientHTTPFailuresPreserveOperationOutcome(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			body := `{"resourceType":"OperationOutcome","issue":[{"diagnostics":"test failure"}]}`
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				io.WriteString(w, body)
			}))
			defer server.Close()
			client := NewClient(Config{FHIRBaseURL: server.URL}, server.Client())
			got, err := client.GetPatient("token", "missing")
			var httpErr *HTTPError
			if !errors.As(err, &httpErr) || httpErr.StatusCode != status {
				t.Fatalf("error = %v, want HTTPError %d", err, status)
			}
			if string(got) != body || string(httpErr.Body) != body {
				t.Fatalf("response body was not preserved")
			}
		})
	}
}

func TestNetworkFailureIsDescriptive(t *testing.T) {
	client := NewClient(Config{FHIRBaseURL: "http://127.0.0.1:1"}, &http.Client{Timeout: 100 * time.Millisecond})
	_, err := client.GetPatient("token", "123")
	if err == nil || !strings.Contains(err.Error(), "network failure") {
		t.Fatalf("error = %v", err)
	}
}

func decodeJWTPart(t *testing.T, encoded string, target any) {
	t.Helper()
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatal(err)
	}
}

func testPrivateKey(t *testing.T, pkcs1 bool) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if pkcs1 {
		block = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	} else {
		encoded, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		block = &pem.Block{Type: "PRIVATE KEY", Bytes: encoded}
	}
	path := filepath.Join(t.TempDir(), "private_key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	return key, path
}

func TestPatientIDIsPathEscaped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if decoded, _ := url.PathUnescape(r.URL.EscapedPath()); decoded != "/Patient/id/with/slash" {
			t.Errorf("escaped path = %q", r.URL.EscapedPath())
		}
		io.WriteString(w, `{}`)
	}))
	defer server.Close()
	client := NewClient(Config{FHIRBaseURL: server.URL}, server.Client())
	if _, err := client.GetPatient("token", "id/with/slash"); err != nil {
		t.Fatal(err)
	}
}
