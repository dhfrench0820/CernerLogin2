package main

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

/* func main() {
	// Sandbox token endpoint for your specific tenant/realm context
	tokenURL := "https://authorization.sandboxcerner.com/tenants/ec2458f2-1e24-41c8-b71b-0e701af7583d/protocols/oauth2/profiles/smart-v1/token"

	clientID := "f931ec0c-f595-48b4-bac9-b65c348957de"
	clientSecret := "XAqmfVfEzWlUmdMa5T_DmkixIe_rDJdU"

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("scope", "system/Patient.read system/Observation.read system/DocumentReference.read") // adjust scopes as needed

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		fmt.Printf("\nLine 32: NewRequest Err")
		panic(err)
	}

	// Confidential apps require Basic Auth header with client_id and client_secret
	fmt.Printf("clientID:secret: " + clientID + ":" + clientSecret + "\n")
	fmt.Printf("Line 37: Secret: %s\n", clientSecret)
	authString := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
	fmt.Printf("38 AuthString: %s\n", authString)
	req.Header.Add("Authorization", "Basic "+authString)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	fmt.Printf("40: after Header set - ")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Line 44:Client.Do err")
		panic(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		panic(fmt.Sprintf("line 50:bad status: %d", resp.StatusCode))
	}

	var tokenRes TokenResponse
	json.NewDecoder(resp.Body).Decode(&tokenRes)

	fmt.Printf("Line 56:Access Token: %s\n", tokenRes.AccessToken)
} */
