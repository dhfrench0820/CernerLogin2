# Cerner Millennium FHIR Go proof of concept

This project demonstrates the two operations needed for a system-to-system Oracle Health (Cerner) Millennium FHIR R4 integration:

1. Create an RS384-signed JWT client assertion and exchange it for an OAuth 2.0 access token.
2. Use that bearer token to retrieve one complete `Patient` resource as raw JSON.

It has no browser redirect, user login, database, or UI. Credentials and tenant-specific URLs are configuration only. JWT is the default authentication method; optional client-secret authentication is available for system accounts configured for Basic OAuth.

## Prerequisites

- Go 1.22 or newer
- An Oracle Health Millennium system application/system account
- The application's client ID and registered JWKS key ID (`kid`)
- The RSA private key corresponding to the registered public key
- A tenant token endpoint, FHIR R4 base URL, and accessible Patient ID

Oracle Health currently advertises RS384 or ES384 for JWT client authentication. This proof of concept implements RSA/RS384. Do not use `https://cerner.com` as either endpoint. Obtain the exact URLs for the target tenant from its `/.well-known/smart-configuration` metadata or the application's sandbox configuration. The token URL must exactly match the JWT `aud` claim.

## Configure

Copy `.env.example` to `.env` as a convenient reference and populate it. The program deliberately does not load `.env` files or add a dotenv dependency; export the values into the process environment before running it.

PowerShell example:

```powershell
$env:CERNER_AUTH_METHOD = "jwt"
$env:CERNER_CLIENT_ID = "your-system-account-client-id"
$env:CERNER_TOKEN_URL = "https://authorization.sandboxcerner.com/tenants/YOUR_TENANT/protocols/oauth2/profiles/smart-v1/token"
$env:CERNER_FHIR_BASE_URL = "https://fhir-ehr-code.cerner.com/r4/YOUR_TENANT"
$env:CERNER_PRIVATE_KEY_PATH = "private_key.pem"
$env:CERNER_KEY_ID = "registered-jwks-key-id"
$env:CERNER_SCOPES = "system/Patient.read"
$env:CERNER_PATIENT_ID = "sandbox-patient-id"
```

`CERNER_SCOPES` is optional and defaults to `system/Patient.read`. `CERNER_HTTP_TIMEOUT` is optional and defaults to `15s` (Go duration syntax).

To reproduce a client-secret system-account test instead of JWT, configure:

```powershell
$env:CERNER_AUTH_METHOD = "client_secret"
$env:CERNER_CLIENT_ID = "your-system-account-client-id"
$env:CERNER_CLIENT_SECRET = "your-rotated-client-secret"
$env:CERNER_TOKEN_URL = "the-exact-discovered-token-endpoint"
$env:CERNER_FHIR_BASE_URL = "your-FHIR-R4-base-URL"
$env:CERNER_SCOPES = "system/Patient.read"
$env:CERNER_PATIENT_ID = "sandbox-patient-id"
```

In `client_secret` mode, `CERNER_PRIVATE_KEY_PATH` and `CERNER_KEY_ID` are not used. Never put the secret in source code.

### RSA key

Generate a new 2048-bit or stronger RSA key if the system account does not already have one:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private_key.pem
openssl pkey -in private_key.pem -pubout -out public_key.pem
```

Register the public key/JWKS with the Oracle Health system account and set `CERNER_KEY_ID` to its registered `kid`. Never commit, email, log, or print the private key. Both PKCS#8 (`BEGIN PRIVATE KEY`) and PKCS#1 (`BEGIN RSA PRIVATE KEY`) PEM files are accepted by this code. Encrypted private keys are intentionally not supported by this minimal demo.

## Run

There are no third-party dependencies, so normal module setup is enough:

```bash
go mod download
go run ./cmd/demo
```

The demo calls `cerner.Authenticate()`, then `cerner.GetPatient(token, patientID)`, and writes the complete Patient JSON to standard output. Treat that output as protected health information in non-sandbox environments.

## Test

Mock tests require no credentials or network access:

```bash
go test -v ./...
```

The live sandbox test is opt-in and uses the same environment variables:

```bash
CERNER_INTEGRATION_TEST=true go test -v ./cerner -run TestSandboxIntegration
```

It is skipped unless `CERNER_INTEGRATION_TEST=true`. It obtains a token, fetches the configured patient, and verifies `resourceType` is `Patient`.

## Common failures

- `400`/`invalid_client`: wrong client ID, unregistered public key, incorrect `kid`, unsupported key/signature, or malformed assertion.
- `400`/`invalid_grant`: JWT `aud` does not exactly equal the token endpoint, assertion timestamps are unacceptable, or the assertion was replayed.
- `401` from Patient: the bearer token is missing, expired, invalid, or issued for a different tenant.
- `403` from Patient: `system/Patient.read` was not granted, the application is not authorized for Patient access, or the tenant disallows the operation.
- `404` from Patient: the ID is not present/visible in that tenant. The returned error includes the original FHIR `OperationOutcome` body.
- Timeout, DNS, connection, or TLS error: verify both URLs, network access, proxy/firewall rules, certificate trust, and `CERNER_HTTP_TIMEOUT`.

HTTP errors report the status and response body, with response size capped at 1 MiB. Client assertions, private keys, and access tokens are never included in errors.

## API

```go
func Authenticate() (string, error)
func GetPatient(token, patientID string) ([]byte, error)
```

`GetPatient` returns the unmodified response body. On an HTTP error it returns both that body and an error, allowing callers to inspect a FHIR `OperationOutcome`.
