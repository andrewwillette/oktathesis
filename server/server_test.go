package main

import (
	"fmt"
	"testing"
)

func TestValidateToken(t *testing.T) {
	// manually added when needed for testing
	var token = ""
	claims, err := validateToken(token)
	if err != nil {
		t.Errorf("Failed to validate token: %v", err)
	}
	fmt.Printf("%v", claims)
}
