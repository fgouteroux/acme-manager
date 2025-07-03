package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/fgouteroux/acme_manager/certstore"
	"github.com/fgouteroux/acme_manager/config"
	"github.com/fgouteroux/acme_manager/queue"
	"github.com/fgouteroux/acme_manager/storage/vault"
	"github.com/fgouteroux/acme_manager/testhelper"
	"github.com/fgouteroux/acme_manager/utils"

	"github.com/stretchr/testify/assert"
)

var (
	logger log.Logger = noOpLogger{}
	mux    *http.ServeMux
)

// noOpLogger is a logger that discards all log messages
type noOpLogger struct{}

// Log implements the log.Logger interface but does nothing
func (noOpLogger) Log(_ ...interface{}) error {
	// Discard all log messages
	return nil
}

func TestMain(m *testing.M) {

	// Example condition to enable or disable logging
	enableLogging := os.Getenv("ENABLE_DEBUG") == "true"

	if enableLogging {
		// Set up logger with level filter.
		logger = log.NewLogfmtLogger(os.Stdout)
		logger = level.NewFilter(logger, level.AllowDebug())
		logger = log.With(logger, "caller", log.DefaultCaller)
	} else {
		// Use the no-op logger
		logger = noOpLogger{}
	}

	amRing := testhelper.GetTestRing(logger)

	certstore.AmStore = &certstore.CertStore{
		RingConfig: amRing,
		Logger:     logger,
	}
	config.SupportedIssuers = []string{"pebble"}
	config.GlobalConfig.Common.APIKeyHash = utils.SHA1Hash("valid-api-key")
	config.GlobalConfig.Common.CertDaysRenewal = "20-30"
	config.GlobalConfig.Common.RootPathAccount = "tests/accounts"
	config.GlobalConfig.Common.RootPathCertificate = "tests/certificates"

	config.GlobalConfig.Issuer = map[string]config.Issuer{
		"pebble": config.Issuer{
			CADirURL:      "https://localhost:14000/dir",
			HTTPChallenge: "kvring",
		},
	}

	certstore.Setup(logger, nil, config.GlobalConfig, "dev")

	// Initialize the KV store with test data
	initKVStoreToken()

	// Create a new ServeMux to register handlers
	mux = http.NewServeMux()

	// Register the .well-known/acme-challenge handler
	mux.HandleFunc("/.well-known/acme-challenge/", func(w http.ResponseWriter, req *http.Request) {
		httpChallengeHandler(w, req)
	})

	// certificate
	mux.Handle("GET /api/v1/certificate/metadata", CertificateMetadataHandler(logger))
	mux.Handle("PUT /api/v1/certificate", UpdateCertificateHandler(logger, nil))
	mux.Handle("POST /api/v1/certificate", CreateCertificateHandler(logger, nil))
	mux.Handle("GET /api/v1/certificate/{issuer}/{domain}", GetCertificateHandler(logger))
	mux.Handle("DELETE /api/v1/certificate/{issuer}/{domain}", DeleteCertificateHandler(logger, nil))

	// token
	mux.Handle("PUT /api/v1/token", UpdateTokenHandler(logger, nil))
	mux.Handle("POST /api/v1/token", CreateTokenHandler(logger, nil))
	mux.Handle("GET /api/v1/token/{id}", GetTokenHandler(logger))
	mux.Handle("DELETE /api/v1/token/{id}", RevokeTokenHandler(logger, nil))

	// init queues
	certstore.CertificateQueue = queue.NewQueue("certificate")
	certstore.ChallengeQueue = queue.NewQueue("challenge")
	certstore.TokenQueue = queue.NewQueue("token")

	// init workers
	tokenWorker := queue.NewWorker(certstore.TokenQueue, logger)
	challengeWorker := queue.NewWorker(certstore.ChallengeQueue, logger)
	certificateWorker := queue.NewWorker(certstore.CertificateQueue, logger)

	// start workers
	go tokenWorker.DoWork()
	go certificateWorker.DoWork()
	go challengeWorker.DoWork()

	// Run the tests
	code := m.Run()

	// Tear down: Clean up if necessary
	os.Exit(code)
}

func initKVStoreToken() {
	data := make(map[string]certstore.Token, 1)
	data["testuser"] = certstore.Token{
		TokenHash: "206c80413b9a96c1312cc346b7d2517b84463edd",
		Scope:     []string{"create", "read", "update", "delete"},
		Username:  "testuser",
		Expires:   "Never",
	}
	certstore.AmStore.PutKVRing(certstore.AmTokenRingKey, data)
	// wait for cert kv store
	time.Sleep(1 * time.Second)
}

// TestAPIAPIResponseJSON checks that the responseJSON function returns the correct status and JSON body
func TestAPIResponseJSON(t *testing.T) {
	rr := httptest.NewRecorder()
	data := map[string]string{"key": "value"}
	responseJSON(rr, data, nil, http.StatusOK)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	expected := `{"key":"value"}`
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}
}

// TestAPIAPICheckAuth checks that the checkAuth function correctly validates the authorization token
func TestAPICheckAuth(t *testing.T) {

	// Create a new request with an authorization header
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer dGVzdHVzZXI6dGVzdHBhc3M=") // Base64 for "testuser:testpass"

	// Call the checkAuth function with the mock store
	token, err := checkAuth(req)

	// Check for errors
	if err != nil {
		t.Errorf("checkAuth returned an error: %v", err)
	}

	// Check the token
	if token.Username != "testuser" {
		t.Errorf("checkAuth returned unexpected username: got %v want %v", token.Username, "testuser")
	}
}

// TestAPICertificateMetadataHandler checks that the handler returns the correct metadata
func TestAPICertificateMetadataHandler(t *testing.T) {

	// init kv store with cert
	var certs []certstore.Certificate
	data := certstore.Certificate{
		Domain: "testfgx.example.com",
		Issuer: "pebble",
		Owner:  "testuser",
	}
	certs = append(certs, data)
	certstore.AmStore.PutKVRing(certstore.AmCertificateRingKey, certs)

	// wait for cert kv store
	time.Sleep(1 * time.Second)

	// init the request
	req, err := http.NewRequest("GET", "/api/v1/certificate/metadata?issuer=pebble&domain=testfgx.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer dGVzdHVzZXI6dGVzdHBhc3M=")

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	expected := `[{"domain":"testfgx.example.com","issuer":"pebble","bundle":false,"expires":"","fingerprint":"","owner":"testuser","csr":"","labels":"","encryption":"","serial":"","key_type":""}]`
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}
}

// TestAPIGetCertificateHandler checks that the handler returns the correct certificate
func TestAPIGetCertificateHandler(t *testing.T) {

	enableLogging := os.Getenv("ENABLE_DEBUG") == "true"
	vaultTest := testhelper.GetTestVaultServer(t, enableLogging)
	defer vaultTest.Cluster.Cleanup()

	vault.GlobalClient = &vaultTest.Client

	issuer := "pebble"
	domain := "testfgx.example.com"

	// init kv store with cert
	var certs []certstore.Certificate
	data := certstore.Certificate{
		Domain: domain,
		Issuer: issuer,
		Owner:  "testuser",
	}
	certs = append(certs, data)
	certstore.AmStore.PutKVRing(certstore.AmCertificateRingKey, certs)

	// wait for cert kv store
	time.Sleep(1 * time.Second)

	err := vault.GlobalClient.PutSecretWithAppRole("/testuser/pebble/testfgx.example.com", utils.StructToMapInterface(data))
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("GET", "/api/v1/certificate/pebble/testfgx.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer dGVzdHVzZXI6dGVzdHBhc3M=")

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	// wait for cert kv store
	time.Sleep(1 * time.Second)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var result certstore.CertMap
	err = json.Unmarshal(rr.Body.Bytes(), &result)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, result.Domain, domain)
	assert.Equal(t, result.Issuer, issuer)
	assert.Equal(t, result.Owner, "testuser")
}

// TestAPICreateCertificateHandler checks that the handler creates a certificate correctly
func TestAPICreateCertificateHandler(t *testing.T) {

	enableLogging := os.Getenv("ENABLE_DEBUG") == "true"

	vaultTest := testhelper.GetTestVaultServer(t, enableLogging)
	defer vaultTest.Cluster.Cleanup()

	vault.GlobalClient = &vaultTest.Client

	// init kv store with cert
	var certs []certstore.Certificate
	data := certstore.Certificate{
		Domain: "testfgx2.example.com",
		Issuer: "pebble",
		Owner:  "testuser",
	}
	certs = append(certs, data)
	certstore.AmStore.PutKVRing(certstore.AmCertificateRingKey, certs)

	// wait for cert kv store
	time.Sleep(1 * time.Second)

	issuer := "pebble"
	domain := "testfgx.example.com"
	csr := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJRENUQ0NBZkVDQVFBd2daSXhIREFhQmdOVkJBTU1FM1JsYzNSbVozZ3VaWGhoYlhCc1pTNWpiMjB4SGpBYwpCZ2txaGtpRzl3MEJDUUVXRDNOemJFQmxlR0Z0Y0d4bExtTnZiVEVRTUE0R0ExVUVDZ3dIVTI5amFXVjBaVEVVCk1CSUdBMVVFQ3d3TFJHVndZWEowWlcxbGJuUXhEakFNQmdOVkJBY01CVlpwYkd4bE1RMHdDd1lEVlFRSURBUkYKZEdGME1Rc3dDUVlEVlFRR0V3SkdVakNDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQgpBTDRodjNORGE1K2hMc215VTlyODB1NWtkc0pxcTFQTXl3RkR5UXFNZ0NFTEUwWHhHOTg4eFNONGFiV24wQ09KCjJ2K0pqKzljcXdvYkVsZ0dJR21YS3FFYXR3SldUT0tUdHBrU3g1M0dkVGZvbklXeFRzTDJxa2F5VWNuanVEakMKWnNGSjJuMXBlOVdINzVEMklzRFduTVJmUU1McjBWUnd4K1o3YWJYWW05L1ltcndSS3FwS1hKR09DbVRQb3ZHaApMTFo5M1lCSkh3UjhJOWJSVDI1cWJXeFVvNEl1YnljTjRKRlYwR04yZklTOVNHd0N5ZEhtczlGN0F4N3ZLaGdPCjFxRVBOeEJaVHdYZFA0cmhOWTh3bEM3Z2tWckFUdmZTT1pDeWxYbm50bER3RUdkWmhwcmNDUThIZlRIUWVteE8KUDV2dEJYSXlJTFJLL1hpdjJpd3hUUHNDQXdFQUFhQXhNQzhHQ1NxR1NJYjNEUUVKRGpFaU1DQXdIZ1lEVlIwUgpCQmN3RllJVGRHVnpkR1puZUM1bGVHRnRjR3hsTG1OdmJUQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFkQk5pClBYNHREVGtocVRRdVAvSlB3ZkRIemRBTDhpamV0NHhNaVBxZEdqdkhaWWh6WVg0WEVvYWtnREF2VmNQN2d0N24KeGRnU2pJUWFxckg2cU9BZGd4WERoWHkwUjlzUG9kaDVqV0w0Qk01aDJEOU5UOXU3cXdUaEhONVp1RmxDbzBBeAoxbnEwTVdmRmU4a2wyY3lMMVFrUWhNQW1OTG5KTWRzN2NuU0R2TVRCUDVwSUV1TndIZGRUMVZNWnJmYUZJejJuCkw3aFJmeWhKMVpRcEFyaE5rTno5Nk1XU2VhcytOZGNSWWVhcWg3M01NS0VBaU4zU0R1OFV5eUlHQUY1UzFvTVIKVzlCMUhEanBOV3VaNWlOUXRSMVNzMGZpUEpxY1dPelJMSUcvSHlIb0l1YkVSNi82K3dEQ255Z0hLOUpudHFlbAo4V2JzSVJrbEpHalY1S0dEbFE9PQotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0K"

	jsonBody := []byte(fmt.Sprintf("{\"domain\":\"%s\",\"issuer\":\"%s\",\"csr\":\"%s\"}", domain, issuer, csr))
	req, err := http.NewRequest("POST", "/api/v1/certificate", bytes.NewBuffer(jsonBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer dGVzdHVzZXI6dGVzdHBhc3M=")
	req.Header.Set("Content-Type", "application/json")

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Serve the HTTP request
	mux.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusCreated {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusCreated)
	}

	var result certstore.CertMap
	err = json.Unmarshal(rr.Body.Bytes(), &result)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, result.Domain, domain)
	assert.Equal(t, result.Issuer, issuer)
	assert.Equal(t, result.Owner, "testuser")

	// Assert that each field is not empty
	assertFieldNotEmpty(t, result.RenewalDate, "RenewalDate")
	assertFieldNotEmpty(t, result.Expires, "Expires")
	assertFieldNotEmpty(t, result.Fingerprint, "Fingerprint")
	assertFieldNotEmpty(t, result.Encryption, "Encryption")
	assertFieldNotEmpty(t, result.Serial, "Serial")
	assertFieldNotEmpty(t, result.Cert, "Cert")
	assertFieldNotEmpty(t, result.CAIssuer, "CaIssuer")
	assertFieldNotEmpty(t, result.URL, "URL")
}

// Helper function to assert that a field is not empty
func assertFieldNotEmpty(t *testing.T, value string, fieldName string) {
	if value == "" {
		t.Errorf("Expected %s to be non-empty, but got an empty string", fieldName)
	}
}

// TestAPIUpdateCertificateHandler checks that the handler updates a certificate correctly
func TestAPIUpdateCertificateHandler(t *testing.T) {

	enableLogging := os.Getenv("ENABLE_DEBUG") == "true"

	vaultTest := testhelper.GetTestVaultServer(t, enableLogging)
	defer vaultTest.Cluster.Cleanup()

	vault.GlobalClient = &vaultTest.Client

	issuer := "pebble"
	domain := "testfgx.example.com"
	csr := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJRENUQ0NBZkVDQVFBd2daSXhIREFhQmdOVkJBTU1FM1JsYzNSbVozZ3VaWGhoYlhCc1pTNWpiMjB4SGpBYwpCZ2txaGtpRzl3MEJDUUVXRDNOemJFQmxlR0Z0Y0d4bExtTnZiVEVRTUE0R0ExVUVDZ3dIVTI5amFXVjBaVEVVCk1CSUdBMVVFQ3d3TFJHVndZWEowWlcxbGJuUXhEakFNQmdOVkJBY01CVlpwYkd4bE1RMHdDd1lEVlFRSURBUkYKZEdGME1Rc3dDUVlEVlFRR0V3SkdVakNDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQgpBTDRodjNORGE1K2hMc215VTlyODB1NWtkc0pxcTFQTXl3RkR5UXFNZ0NFTEUwWHhHOTg4eFNONGFiV24wQ09KCjJ2K0pqKzljcXdvYkVsZ0dJR21YS3FFYXR3SldUT0tUdHBrU3g1M0dkVGZvbklXeFRzTDJxa2F5VWNuanVEakMKWnNGSjJuMXBlOVdINzVEMklzRFduTVJmUU1McjBWUnd4K1o3YWJYWW05L1ltcndSS3FwS1hKR09DbVRQb3ZHaApMTFo5M1lCSkh3UjhJOWJSVDI1cWJXeFVvNEl1YnljTjRKRlYwR04yZklTOVNHd0N5ZEhtczlGN0F4N3ZLaGdPCjFxRVBOeEJaVHdYZFA0cmhOWTh3bEM3Z2tWckFUdmZTT1pDeWxYbm50bER3RUdkWmhwcmNDUThIZlRIUWVteE8KUDV2dEJYSXlJTFJLL1hpdjJpd3hUUHNDQXdFQUFhQXhNQzhHQ1NxR1NJYjNEUUVKRGpFaU1DQXdIZ1lEVlIwUgpCQmN3RllJVGRHVnpkR1puZUM1bGVHRnRjR3hsTG1OdmJUQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFkQk5pClBYNHREVGtocVRRdVAvSlB3ZkRIemRBTDhpamV0NHhNaVBxZEdqdkhaWWh6WVg0WEVvYWtnREF2VmNQN2d0N24KeGRnU2pJUWFxckg2cU9BZGd4WERoWHkwUjlzUG9kaDVqV0w0Qk01aDJEOU5UOXU3cXdUaEhONVp1RmxDbzBBeAoxbnEwTVdmRmU4a2wyY3lMMVFrUWhNQW1OTG5KTWRzN2NuU0R2TVRCUDVwSUV1TndIZGRUMVZNWnJmYUZJejJuCkw3aFJmeWhKMVpRcEFyaE5rTno5Nk1XU2VhcytOZGNSWWVhcWg3M01NS0VBaU4zU0R1OFV5eUlHQUY1UzFvTVIKVzlCMUhEanBOV3VaNWlOUXRSMVNzMGZpUEpxY1dPelJMSUcvSHlIb0l1YkVSNi82K3dEQ255Z0hLOUpudHFlbAo4V2JzSVJrbEpHalY1S0dEbFE9PQotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0K"

	// init kv store with cert
	var certs []certstore.Certificate
	data := certstore.Certificate{
		Domain: domain,
		Issuer: issuer,
		Owner:  "testuser",
		CSR:    csr,
		Days:   30,
	}
	certs = append(certs, data)
	certstore.AmStore.PutKVRing(certstore.AmCertificateRingKey, certs)

	// wait for cert kv store
	time.Sleep(1 * time.Second)

	jsonBody := []byte(fmt.Sprintf("{\"domain\":\"%s\",\"issuer\":\"%s\",\"csr\":\"%s\"}", domain, issuer, csr))
	req, err := http.NewRequest("PUT", "/api/v1/certificate", bytes.NewBuffer(jsonBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer dGVzdHVzZXI6dGVzdHBhc3M=")
	req.Header.Set("Content-Type", "application/json")

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Serve the HTTP request
	mux.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var result certstore.CertMap
	err = json.Unmarshal(rr.Body.Bytes(), &result)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, result.Domain, domain)
	assert.Equal(t, result.Issuer, issuer)
	assert.Equal(t, result.Owner, "testuser")
	assert.Equal(t, result.CSR, csr)

	// Assert that each field is not empty
	assertFieldNotEmpty(t, result.RenewalDate, "RenewalDate")
	assertFieldNotEmpty(t, result.Expires, "Expires")
	assertFieldNotEmpty(t, result.Fingerprint, "Fingerprint")
	assertFieldNotEmpty(t, result.Encryption, "Encryption")
	assertFieldNotEmpty(t, result.Serial, "Serial")
	assertFieldNotEmpty(t, result.Cert, "Cert")
	assertFieldNotEmpty(t, result.CAIssuer, "CaIssuer")
	assertFieldNotEmpty(t, result.URL, "URL")
}

// TestAPIDeleteCertificateHandler checks that the handler deletes a certificate correctly
func TestAPIDeleteCertificateHandler(t *testing.T) {

	enableLogging := os.Getenv("ENABLE_DEBUG") == "true"

	vaultTest := testhelper.GetTestVaultServer(t, enableLogging)
	defer vaultTest.Cluster.Cleanup()

	vault.GlobalClient = &vaultTest.Client

	issuer := "pebble"
	domain := "testfgx.example.com"
	csr := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJRENUQ0NBZkVDQVFBd2daSXhIREFhQmdOVkJBTU1FM1JsYzNSbVozZ3VaWGhoYlhCc1pTNWpiMjB4SGpBYwpCZ2txaGtpRzl3MEJDUUVXRDNOemJFQmxlR0Z0Y0d4bExtTnZiVEVRTUE0R0ExVUVDZ3dIVTI5amFXVjBaVEVVCk1CSUdBMVVFQ3d3TFJHVndZWEowWlcxbGJuUXhEakFNQmdOVkJBY01CVlpwYkd4bE1RMHdDd1lEVlFRSURBUkYKZEdGME1Rc3dDUVlEVlFRR0V3SkdVakNDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQgpBTDRodjNORGE1K2hMc215VTlyODB1NWtkc0pxcTFQTXl3RkR5UXFNZ0NFTEUwWHhHOTg4eFNONGFiV24wQ09KCjJ2K0pqKzljcXdvYkVsZ0dJR21YS3FFYXR3SldUT0tUdHBrU3g1M0dkVGZvbklXeFRzTDJxa2F5VWNuanVEakMKWnNGSjJuMXBlOVdINzVEMklzRFduTVJmUU1McjBWUnd4K1o3YWJYWW05L1ltcndSS3FwS1hKR09DbVRQb3ZHaApMTFo5M1lCSkh3UjhJOWJSVDI1cWJXeFVvNEl1YnljTjRKRlYwR04yZklTOVNHd0N5ZEhtczlGN0F4N3ZLaGdPCjFxRVBOeEJaVHdYZFA0cmhOWTh3bEM3Z2tWckFUdmZTT1pDeWxYbm50bER3RUdkWmhwcmNDUThIZlRIUWVteE8KUDV2dEJYSXlJTFJLL1hpdjJpd3hUUHNDQXdFQUFhQXhNQzhHQ1NxR1NJYjNEUUVKRGpFaU1DQXdIZ1lEVlIwUgpCQmN3RllJVGRHVnpkR1puZUM1bGVHRnRjR3hsTG1OdmJUQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFkQk5pClBYNHREVGtocVRRdVAvSlB3ZkRIemRBTDhpamV0NHhNaVBxZEdqdkhaWWh6WVg0WEVvYWtnREF2VmNQN2d0N24KeGRnU2pJUWFxckg2cU9BZGd4WERoWHkwUjlzUG9kaDVqV0w0Qk01aDJEOU5UOXU3cXdUaEhONVp1RmxDbzBBeAoxbnEwTVdmRmU4a2wyY3lMMVFrUWhNQW1OTG5KTWRzN2NuU0R2TVRCUDVwSUV1TndIZGRUMVZNWnJmYUZJejJuCkw3aFJmeWhKMVpRcEFyaE5rTno5Nk1XU2VhcytOZGNSWWVhcWg3M01NS0VBaU4zU0R1OFV5eUlHQUY1UzFvTVIKVzlCMUhEanBOV3VaNWlOUXRSMVNzMGZpUEpxY1dPelJMSUcvSHlIb0l1YkVSNi82K3dEQ255Z0hLOUpudHFlbAo4V2JzSVJrbEpHalY1S0dEbFE9PQotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0K"

	// init kv store with cert
	var certs []certstore.Certificate
	data := certstore.Certificate{
		Domain: domain,
		Issuer: issuer,
		Owner:  "testuser",
		CSR:    csr,
	}
	certs = append(certs, data)
	certstore.AmStore.PutKVRing(certstore.AmCertificateRingKey, certs)

	// wait for cert kv store
	time.Sleep(1 * time.Second)

	err := vault.GlobalClient.PutSecretWithAppRole("/testuser/pebble/testfgx.example.com", utils.StructToMapInterface(data))
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("DELETE", "/api/v1/certificate/pebble/testfgx.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer dGVzdHVzZXI6dGVzdHBhc3M=")

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusNoContent {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusNoContent)
	}
}

func httpChallengeHandler(w http.ResponseWriter, r *http.Request) {
	data, err := certstore.AmStore.GetKVRingMapString(certstore.AmChallengeRingKey, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	if val, ok := data[r.RequestURI]; ok {
		_, _ = io.WriteString(w, val)
	} else {
		http.Error(w, fmt.Sprintf("key %s not found", r.RequestURI), http.StatusNotFound)
	}
}
