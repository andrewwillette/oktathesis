package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

var (
	oktaDomain  = "https://dev-v2ckea25dc8izr13.us.auth0.com"
	apiAudience = "https://oktathesis"
)

func main() {
	http.HandleFunc("/validate", validateTokenHandler)
	fmt.Println("Server is running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func validateTokenHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}

	// Extract the token from the "Bearer <token>" format
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
		return
	}

	// Validate the token
	claims, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
		return
	}

	// Respond with success and token claims
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"message": "Token is valid", "claims": %v}`, claims)
}

func validateToken(tokenString string) (jwt.MapClaims, error) {
	// Parse and validate the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure the token's signing method is what you expect
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Fetch the Okta JSON Web Key Set (JWKS)
		oktaDomain = "https://dev-v2ckea25dc8izr13.us.auth0.com"
		jwksURL := fmt.Sprintf("%s/.well-known/jwks.json", oktaDomain)
		keys, err := fetchJWKS(jwksURL)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
		}

		// Extract the signing key based on the token's "kid" header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}
		key := keys[kid]
		if key == nil {
			return nil, fmt.Errorf("key not found for kid: %s", kid)
		}

		return key, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if claims["aud"] != apiAudience {
			return nil, fmt.Errorf("invalid audience: %v", claims["aud"])
		}
		issuer := strings.TrimSuffix(claims["iss"].(string), "/")
		if issuer != oktaDomain {
			return nil, fmt.Errorf("invalid issuer: %v", claims["iss"])
		}
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}

func fetchJWKS(url string) (map[string]interface{}, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch JWKS: %s", resp.Status)
	}

	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}

	keys := make(map[string]interface{})
	for _, key := range jwks.Keys {
		// Decode modulus and exponent
		nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			return nil, fmt.Errorf("failed to decode modulus: %v", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			return nil, fmt.Errorf("failed to decode exponent: %v", err)
		}

		// Convert bytes to big.Int
		n := new(big.Int).SetBytes(nBytes)
		e := int(new(big.Int).SetBytes(eBytes).Int64())

		// Create RSA public key
		keys[key.Kid] = &rsa.PublicKey{
			N: n,
			E: e,
		}
	}
	return keys, nil
}
