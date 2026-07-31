package main

import (
	"fmt"
	"os"
	"strings"

	"cerner-fhir-go/cerner"
)

func main() {
	patientID := strings.TrimSpace(os.Getenv("CERNER_PATIENT_ID"))
	if patientID == "" {
		fail(fmt.Errorf("required configuration CERNER_PATIENT_ID is empty"))
	}
	token, err := cerner.Authenticate()
	if err != nil {
		fail(err)
	}
	patient, err := cerner.GetPatient(token, patientID)
	if err != nil {
		fail(err)
	}
	if _, err := os.Stdout.Write(append(patient, '\n')); err != nil {
		fail(fmt.Errorf("write patient JSON: %w", err))
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "cerner demo:", err)
	os.Exit(1)
}
