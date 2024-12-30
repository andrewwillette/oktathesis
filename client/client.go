package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

var (
	oktaDomain   = os.Getenv("OKTA_DOMAIN")
	clientID     = os.Getenv("OKTA_CLIENT_ID")
	clientSecret = os.Getenv("OKTA_CLIENT_SECRET")
)

func main() {
	token := generateToken()
	fmt.Printf("token: %s\n", token)
	response, err := sendRequest(token)
	if err != nil {
		log.Fatalf("Failed to validate token: %v", err)
	}
	fmt.Println("Server Response:", response)
}

func generateToken() string {
	if oktaDomain == "" || clientID == "" || clientSecret == "" {
		log.Fatalf("Missing required environment variables")
	}
	tokenURL := fmt.Sprintf("%s/oauth/token", oktaDomain)
	client := &http.Client{}

	// Request body
	data := map[string]string{
		"grant_type": "client_credentials",
		// "scope":         "openid profile email",
		"client_id":     clientID,
		"client_secret": clientSecret,
		"audience":      "https://oktathesis",
	}
	body, _ := json.Marshal(data)

	req, err := http.NewRequest("POST", tokenURL, bytes.NewBuffer(body))
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("content-type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Failed to get response: %v", err)
	}
	defer resp.Body.Close()

	var result bytes.Buffer
	_, err = io.Copy(&result, resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Failed to get token: %s", result.String())
	}

	var tokenResponse map[string]interface{}
	err = json.Unmarshal(result.Bytes(), &tokenResponse)
	if err != nil {
		log.Fatalf("Failed to unmarshal response: %v", err)
	}
	accesstoken := tokenResponse["access_token"].(string)
	return accesstoken
}

func sendRequest(token string) (string, error) {
	serverURL := "http://localhost:8080/validate"

	client := &http.Client{}
	req, err := http.NewRequest("POST", serverURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	// Add the token to the Authorization header
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorBody bytes.Buffer
		io.Copy(&errorBody, resp.Body)
		return "", fmt.Errorf("server returned error: %s", errorBody.String())
	}

	var responseBody bytes.Buffer
	_, err = io.Copy(&responseBody, resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	return responseBody.String(), nil
}
