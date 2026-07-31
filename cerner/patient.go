package cerner

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// GetPatient reads environment configuration and returns the complete raw resource body.
func GetPatient(token, patientID string) ([]byte, error) {
	client, err := NewClientFromEnv()
	if err != nil {
		return nil, err
	}
	return client.GetPatient(token, patientID)
}

// GetPatient retrieves Patient/{id}. On an HTTP error, body contains the server response.
func (c *Client) GetPatient(token, patientID string) ([]byte, error) {
	if err := require(map[string]string{
		"CERNER_FHIR_BASE_URL": c.Config.FHIRBaseURL, "access token": token, "patient ID": patientID,
	}); err != nil {
		return nil, err
	}
	endpoint := strings.TrimRight(c.Config.FHIRBaseURL, "/") + "/Patient/" + url.PathEscape(patientID)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create patient request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/fhir+json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("patient request network failure: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read patient response: %w", err)
	}
	if len(body) > maxBodyBytes {
		return nil, fmt.Errorf("patient response exceeded %d bytes", maxBodyBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		operation := "FHIR Patient request"
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			operation += " (access token may be expired or invalid)"
		case http.StatusForbidden:
			operation += " (scope or tenant permission may be insufficient)"
		case http.StatusNotFound:
			operation += " (patient was not found)"
		}
		return body, &HTTPError{Operation: operation, StatusCode: resp.StatusCode, Status: resp.Status, Body: body}
	}
	return body, nil
}
