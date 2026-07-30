package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Configuration Constants Intelligent Delivery
const (
	tokenURL      = "https://cerner.com"
	fhirBase      = "https://cerner.com" // Secure R4 Endpoint
	clientID      = "a48019b4-6c6c-4348-b731-057141832d8f"
	keyID         = "YOUR_KEY_ID" // Registered public key ID in Cerner Code Console
	patientID     = "12769853"    // Replace with target R4 Patient ID
	ApplicationID = "22dd2bf2-7998-42b5-a9c5-6ca6cb272d39"
	M7iyawV83sP54qVFpQlghOoObdYCGONl
)

//https://www.freelancer.com/users/l.php?url=https:%2F%2Ffhir-ehr-code.cerner.com%2Fr4%2Fec2458f2-1e24-41c8-b71b-0e701af7583d&sig=3f72a45ce61dd2aba43b31a97148baf0d2afe6d276123394bca65ed96d1779ea

// Structs for Token Handling
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// Minimal Structs for Parsing FHIR R4 Responses
type Patient struct {
	ResourceType string `json:"resourceType"`
	ID           string `json:"id"`
	Name         []struct {
		Text string `json:"text"`
	} `json:"name"`
}

type DocumentReferenceBundle struct {
	ResourceType string `json:"resourceType"`
	Entry        []struct {
		Resource struct {
			ResourceType string `json:"resourceType"`
			ID           string `json:"id"`
			Content      []struct {
				Attachment struct {
					ContentType string `json:"contentType"`
					URL         string `json:"url"`
				} `json:"attachment"`
			} `json:"content"`
		} `json:"resource"`
	} `json:"entry"`
}

func createClientAssertion(privateKeyPath string) (string, error) {
	keyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read private key: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("key is not an RSA private key")
	}

	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    clientID,
		Subject:   clientID,
		Audience:  jwt.ClaimStrings{tokenURL},
		ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
		NotBefore: jwt.NewNumericDate(now),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        fmt.Sprintf("%d", now.UnixNano()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID

	return token.SignedString(rsaKey)
}

func getAccessToken(privateKeyPath string) (string, error) {
	assertion, err := createClientAssertion(privateKeyPath)
	if err != nil {
		return "", err
	}

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	// Requesting system-level scopes required for R4 resources
	data.Set("scope", "system/Patient.read system/DocumentReference.read")
	data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Set("client_assertion", assertion)

	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request failed (Status %d): %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", err
	}
	return tokenResp.AccessToken, nil
}

func makeFHIRRequest(token, url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Accept", "application/fhir+json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("FHIR server returned status %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func downloadBinaryDocument(token, binaryURL, filename string) error {
	req, err := http.NewRequest("GET", binaryURL, nil)
	if err != nil {
		return err
	}

	req.Header.Add("Authorization", "Bearer "+token)
	// Server returns the true file type (e.g., application/pdf) at this endpoint
	req.Header.Add("Accept", "*/*")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download document, status: %d", resp.StatusCode)
	}

	out, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func main() {
	privateKeyFile := "private_key.pem"

	fmt.Println("Authenticating via OAuth2 Client Credentials...")
	token, err := getAccessToken(privateKeyFile)
	if err != nil {
		fmt.Printf("Authentication failed: %v\n", err)
		return
	}

	// 1. Fetch Patient Resource
	fmt.Printf("\nFetching R4 Patient data for ID: %s...\n", patientID)
	patientData, err := makeFHIRRequest(token, fmt.Sprintf("%s/Patient/%s", fhirBase, patientID))
	if err != nil {
		fmt.Printf("Error fetching patient: %v\n", err)
		return
	}

	var pt Patient
	if err := json.Unmarshal(patientData, &pt); err == nil && len(pt.Name) > 0 {
		fmt.Printf("Successfully retrieved Patient: %s\n", pt.Name[0].Text)
	}

	// 2. Fetch DocumentReference Bundle
	fmt.Println("\nSearching for DocumentReferences...")
	docRefURL := fmt.Sprintf("%s/DocumentReference?patient=%s", fhirBase, patientID)
	bundleData, err := makeFHIRRequest(token, docRefURL)
	if err != nil {
		fmt.Printf("Error fetching documents: %v\n", err)
		return
	}

	var bundle DocumentReferenceBundle
	if err := json.Unmarshal(bundleData, &bundle); err != nil {
		fmt.Printf("Error unmarshaling bundle: %v\n", err)
		return
	}

	fmt.Printf("Found %d document entry/entries.\n", len(bundle.Entry))

	// 3. Process Content and Stream the Underlying File
	for i, entry := range bundle.Entry {
		doc := entry.Resource
		if len(doc.Content) == 0 {
			continue
		}

		attachment := doc.Content[0].Attachment
		fmt.Printf("[%d] Document ID: %s (%s)\n", i+1, doc.ID, attachment.ContentType)

		if attachment.URL != "" {
			outputFile := fmt.Sprintf("downloaded_doc_%s.dat", doc.ID)
			fmt.Printf(" -> Streaming attachment from: %s\n", attachment.URL)

			err := downloadBinaryDocument(token, attachment.URL, outputFile)
			if err != nil {
				fmt.Printf(" -> Error downloading document: %v\n", err)
			} else {
				fmt.Printf(" -> Saved file to %s\n", outputFile)
			}
		}
	}
}
