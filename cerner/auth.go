package cerner

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	maxBodyBytes  = 1 << 20
)

// Authenticate reads environment configuration and returns an access token.
func Authenticate() (string, error) {
	client, err := NewClientFromEnv()
	if err != nil {
		return "", err
	}
	return client.Authenticate()
}

// Authenticate exchanges configured system-account credentials for an access token.
func (c *Client) Authenticate() (string, error) {
	if err := require(map[string]string{"CERNER_CLIENT_ID": c.Config.ClientID, "CERNER_TOKEN_URL": c.Config.TokenURL}); err != nil {
		return "", err
	}

	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {strings.TrimSpace(c.Config.Scopes)},
	}
	authMethod := strings.ToLower(strings.TrimSpace(c.Config.AuthMethod))
	if authMethod == "" {
		authMethod = "jwt"
	}
	switch authMethod {
	case "jwt":
		if err := require(map[string]string{
			"CERNER_PRIVATE_KEY_PATH": c.Config.PrivateKeyPath,
			"CERNER_KEY_ID":           c.Config.KeyID,
		}); err != nil {
			return "", err
		}
		assertion, err := c.clientAssertion()
		if err != nil {
			return "", fmt.Errorf("create client assertion: %w", err)
		}
		form.Set("client_assertion_type", assertionType)
		form.Set("client_assertion", assertion)
	case "client_secret":
		if err := require(map[string]string{"CERNER_CLIENT_SECRET": c.Config.ClientSecret}); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("CERNER_AUTH_METHOD must be jwt or client_secret, got %q", c.Config.AuthMethod)
	}
	req, err := http.NewRequest(http.MethodPost, c.Config.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if authMethod == "client_secret" {
		req.SetBasicAuth(c.Config.ClientID, c.Config.ClientSecret)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request network failure: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return "", fmt.Errorf("read token response: %w", err)
	}
	if len(body) > maxBodyBytes {
		return "", fmt.Errorf("token response exceeded %d bytes", maxBodyBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", &HTTPError{Operation: "authentication", StatusCode: resp.StatusCode, Status: resp.Status, Body: body}
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if strings.TrimSpace(result.AccessToken) == "" {
		return "", fmt.Errorf("token response did not contain access_token")
	}
	return result.AccessToken, nil
}

func (c *Client) clientAssertion() (string, error) {
	keyPEM, err := os.ReadFile(c.Config.PrivateKeyPath)
	if err != nil {
		return "", fmt.Errorf("read private key: %w", err)
	}
	key, err := parseRSAPrivateKey(keyPEM)
	if err != nil {
		return "", err
	}

	now := c.now().UTC()
	jtiBytes := make([]byte, 16)
	randomRead := rand.Read
	if c.rand != nil {
		randomRead = c.rand
	}
	if _, err := randomRead(jtiBytes); err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}
	header, _ := json.Marshal(map[string]string{"alg": "RS384", "kid": c.Config.KeyID, "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss": c.Config.ClientID, "sub": c.Config.ClientID, "aud": c.Config.TokenURL,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "jti": hex.EncodeToString(jtiBytes),
	})
	encoded := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha512.Sum384([]byte(encoded))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA384, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign assertion: %w", err)
	}
	return encoded + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func parseRSAPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("private key is not PEM encoded")
	}
	if x509.IsEncryptedPEMBlock(block) {
		return nil, fmt.Errorf("encrypted PEM private keys are not supported")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 private key is not RSA")
		}
		return rsaKey, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("parse RSA private key: expected PKCS#8 or PKCS#1 PEM")
}
