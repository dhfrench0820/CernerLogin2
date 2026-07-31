package cerner

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestSandboxIntegration(t *testing.T) {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("CERNER_INTEGRATION_TEST")), "true") {
		t.Skip("set CERNER_INTEGRATION_TEST=true to run against a configured sandbox")
	}
	patientID := strings.TrimSpace(os.Getenv("CERNER_PATIENT_ID"))
	if patientID == "" {
		t.Fatal("CERNER_PATIENT_ID is required for the sandbox integration test")
	}
	token, err := Authenticate()
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if token == "" {
		t.Fatal("Authenticate returned an empty token")
	}
	body, err := GetPatient(token, patientID)
	if err != nil {
		t.Fatalf("GetPatient: %v", err)
	}
	var resource struct {
		ResourceType string `json:"resourceType"`
	}
	if err := json.Unmarshal(body, &resource); err != nil {
		t.Fatalf("patient response is not JSON: %v", err)
	}
	if resource.ResourceType != "Patient" {
		t.Fatalf("resourceType = %q, want Patient", resource.ResourceType)
	}
}
