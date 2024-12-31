package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
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
	http.HandleFunc("/", serveForm)
	http.HandleFunc("/submit", handleSubmit)

	fmt.Println("Client server is running on http://localhost:8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

func generateToken(clientID, clientSecret string) (string, error) {
	if oktaDomain == "" || clientID == "" || clientSecret == "" {
		log.Fatalf("Missing required environment variables")
	}
	tokenURL := fmt.Sprintf("%s/oauth/token", oktaDomain)
	client := &http.Client{}

	// Request body
	data := map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     clientID,
		"client_secret": clientSecret,
		"audience":      "https://oktathesis",
	}
	body, _ := json.Marshal(data)

	req, err := http.NewRequest("POST", tokenURL, bytes.NewBuffer(body))
	if err != nil {
		return "", fmt.Errorf("Failed to create request: %v", err)
	}
	req.Header.Set("content-type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Failed to get response: %v", err)
	}
	defer resp.Body.Close()

	var result bytes.Buffer
	_, err = io.Copy(&result, resp.Body)
	if err != nil {
		return "", fmt.Errorf("Failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Failed to get token: %s", result.String())
	}

	var tokenResponse map[string]interface{}
	err = json.Unmarshal(result.Bytes(), &tokenResponse)
	if err != nil {
		return "", err
	}
	accesstoken := tokenResponse["access_token"].(string)
	return accesstoken, nil
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

// Serve the HTML form
func serveForm(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/form.html")
	if err != nil {
		fmt.Println("Error parsing form template:", err)
		http.Error(w, "Error rendering form", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

// Handle form submission
func handleSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	clientID := r.FormValue("clientID")
	clientSecret := r.FormValue("clientSecret")

	if clientID == "" || clientSecret == "" {
		http.Error(w, "Missing clientID or clientSecret", http.StatusBadRequest)
		return
	}

	// Generate token
	token, err := generateToken(clientID, clientSecret)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error generating token: %v", err), http.StatusInternalServerError)
		return
	}

	// Validate token
	response, err := sendRequest(token)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error validating token: %v", err), http.StatusInternalServerError)
		return
	}

	// Send response back to the user
	fmt.Fprintf(w, "Token validation response: %s", response)
}
