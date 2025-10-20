package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/fgouteroux/acme-manager/certstore"
	"github.com/fgouteroux/acme-manager/models"
	"github.com/fgouteroux/acme-manager/storage/vault"
	"github.com/fgouteroux/acme-manager/testhelper"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestGetTokenHandler(t *testing.T) {
	// Test case 1: Valid token ID
	req := httptest.NewRequest("GET", "/api/v1/token/testuser", nil)
	req.Header.Set("X-API-Key", "valid-api-key")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", w.Code)
	}

	// Test case 2: Missing X-API-Key header
	req = httptest.NewRequest("GET", "/api/v1/token/testuser", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status code 401, got %d", w.Code)
	}

	// Test case 3: Invalid API key
	req = httptest.NewRequest("GET", "/api/v1/token/testuser", nil)
	req.Header.Set("X-API-Key", "invalid-api-key")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status code 401, got %d", w.Code)
	}

	// Test case 4: Token ID not found
	req = httptest.NewRequest("GET", "/api/v1/token/invalid-id", nil)
	req.Header.Set("X-API-Key", "valid-api-key")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status code 404, got %d", w.Code)
	}
}

func TestCreateTokenHandler(t *testing.T) {

	enableLogging := os.Getenv("ENABLE_DEBUG") == "true"
	vaultTest := testhelper.GetTestVaultServer(t, enableLogging)
	defer vaultTest.Cluster.Cleanup()

	vault.GlobalClient = &vaultTest.Client

	// Test case 1: Valid token creation
	tokenParams := TokenParams{
		Username: "testuser",
		Scope:    []string{"create", "read", "update", "delete"},
		Duration: "30d",
	}
	body, _ := json.Marshal(tokenParams)
	req := httptest.NewRequest("POST", "/api/v1/token", bytes.NewReader(body))
	req.Header.Set("X-API-Key", "valid-api-key")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status code 201, got %d", w.Code)
	}

	// Test case 2: Missing X-API-Key header
	req = httptest.NewRequest("POST", "/api/v1/token", bytes.NewReader(body))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status code 401, got %d", w.Code)
	}

	// Test case 3: Invalid API key
	req = httptest.NewRequest("POST", "/api/v1/token", bytes.NewReader(body))
	req.Header.Set("X-API-Key", "invalid-api-key")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status code 401, got %d", w.Code)
	}

	// Test case 4: Invalid token parameters
	invalidTokenParams := TokenParams{
		ID:       "valid-id",
		Username: "",
		Scope:    []string{"read", "write"},
		Duration: "30d",
	}
	body, _ = json.Marshal(invalidTokenParams)
	req = httptest.NewRequest("POST", "/api/v1/token", bytes.NewReader(body))
	req.Header.Set("X-API-Key", "valid-api-key")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status code 400, got %d", w.Code)
	}
}

func TestUpdateTokenHandler(t *testing.T) {

	enableLogging := os.Getenv("ENABLE_DEBUG") == "true"
	vaultTest := testhelper.GetTestVaultServer(t, enableLogging)
	defer vaultTest.Cluster.Cleanup()

	vault.GlobalClient = &vaultTest.Client

	// Test case 1: Valid token update
	tokenParams := TokenParams{
		ID:       "testuser",
		Username: "testuser",
		Scope:    []string{"create", "read", "update", "delete"},
		Duration: "30d",
	}
	body, _ := json.Marshal(tokenParams)
	req := httptest.NewRequest("PUT", "/api/v1/token", bytes.NewReader(body))
	req.Header.Set("X-API-Key", "valid-api-key")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", w.Code)
	}

	// Test case 2: Missing X-API-Key header
	req = httptest.NewRequest("PUT", "/api/v1/token", bytes.NewReader(body))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status code 401, got %d", w.Code)
	}

	// Test case 3: Invalid API key
	req = httptest.NewRequest("PUT", "/api/v1/token", bytes.NewReader(body))
	req.Header.Set("X-API-Key", "invalid-api-key")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status code 401, got %d", w.Code)
	}

	// Test case 4: Invalid token parameters
	invalidTokenParams := TokenParams{
		ID:       "testuser",
		Username: "",
		Scope:    []string{"read", "write"},
		Duration: "30d",
	}
	body, _ = json.Marshal(invalidTokenParams)
	req = httptest.NewRequest("PUT", "/api/v1/token", bytes.NewReader(body))
	req.Header.Set("X-API-Key", "valid-api-key")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status code 400, got %d", w.Code)
	}
}

func TestRevokeTokenHandler(t *testing.T) {

	enableLogging := os.Getenv("ENABLE_DEBUG") == "true"
	vaultTest := testhelper.GetTestVaultServer(t, enableLogging)
	defer vaultTest.Cluster.Cleanup()

	vault.GlobalClient = &vaultTest.Client

	err := vaultTest.Client.PutSecretWithAppRole("/token/testuser/valid-id", map[string]interface{}{"foo": "bar"})
	if err != nil {
		t.Fatal(err)
	}

	token := &models.Token{
		TokenHash: "abc123def456",
		Scope:     []string{"create", "read", "update", "delete"},
		Username:  "testuser",
		Expires:   "Never",
	}
	certstore.AmStore.PutToken("valid-id", token)
	// wait for cert kv store
	time.Sleep(1 * time.Second)

	// Test case 1: Valid token revocation
	req := httptest.NewRequest("DELETE", "/api/v1/token/valid-id", nil)
	req.Header.Set("X-API-Key", "valid-api-key")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected status code 204, got %d", w.Code)
	}
	fmt.Println(w.Body.String())

	// Test case 2: Missing X-API-Key header
	req = httptest.NewRequest("DELETE", "/api/v1/token/valid-id", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status code 401, got %d", w.Code)
	}

	// Test case 3: Invalid API key
	req = httptest.NewRequest("DELETE", "/api/v1/token/valid-id", nil)
	req.Header.Set("X-API-Key", "invalid-api-key")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status code 401, got %d", w.Code)
	}

	// Test case 4: Token ID not found
	req = httptest.NewRequest("DELETE", "/api/v1/token/invalid-id", nil)
	req.Header.Set("X-API-Key", "valid-api-key")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status code 404, got %d", w.Code)
	}
}
