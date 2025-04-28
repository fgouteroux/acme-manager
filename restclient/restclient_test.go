package restclient

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/fgouteroux/acme_manager/api"
	"github.com/fgouteroux/acme_manager/certstore"
)

// MockHTTPClient is a mock implementation of http.Client
type MockHTTPClient struct {
	mock.Mock
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*http.Response), args.Error(1)
}

func TestNewClient(t *testing.T) {
	client, err := NewClient("http://example.com", "token", "", "", "", false)
	assert.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, "http://example.com", client.BaseURL)
	assert.Equal(t, "token", client.Token)
}

func TestGetAllCertificateMetadata(t *testing.T) {
	mockClient := &MockHTTPClient{}
	client := &Client{
		BaseURL: "http://example.com",
		Token:   "token",
		httpclient: &http.Client{
			Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				return mockClient.Do(req)
			}),
		},
	}

	response := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBufferString(`[{"issuer":"issuer1","domain":"domain1"}]`)),
	}

	mockClient.On("Do", mock.Anything).Return(response, nil)

	certificates, err := client.GetAllCertificateMetadata()
	assert.NoError(t, err)
	assert.Len(t, certificates, 1)
	assert.Equal(t, "issuer1", certificates[0].Issuer)
	assert.Equal(t, "domain1", certificates[0].Domain)
}

func TestGetCertificateMetadata(t *testing.T) {
	mockClient := &MockHTTPClient{}
	client := &Client{
		BaseURL: "http://example.com",
		Token:   "token",
		httpclient: &http.Client{
			Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				return mockClient.Do(req)
			}),
		},
	}

	response := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBufferString(`{"issuer":"issuer1","domain":"domain1"}`)),
	}

	mockClient.On("Do", mock.Anything).Return(response, nil)

	certificate, err := client.GetCertificateMetadata("issuer1", "domain1")
	assert.NoError(t, err)
	assert.Equal(t, "issuer1", certificate.Issuer)
	assert.Equal(t, "domain1", certificate.Domain)
}

func TestReadCertificate(t *testing.T) {
	mockClient := &MockHTTPClient{}
	client := &Client{
		BaseURL: "http://example.com",
		Token:   "token",
		httpclient: &http.Client{
			Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				return mockClient.Do(req)
			}),
		},
	}

	response := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBufferString(`{"issuer":"issuer1","domain":"domain1","cert":"cert-value","ca_issuer":"ca-issuer-value"}`)),
	}

	mockClient.On("Do", mock.Anything).Return(response, nil)

	certData := certstore.Certificate{Issuer: "issuer1", Domain: "domain1"}
	certificate, err := client.ReadCertificate(certData)
	assert.NoError(t, err)
	assert.Equal(t, "cert-value", certificate.Cert)
	assert.Equal(t, "ca-issuer-value", certificate.CAIssuer)
}

func TestCreateCertificate(t *testing.T) {
	mockClient := &MockHTTPClient{}
	client := &Client{
		BaseURL: "http://example.com",
		Token:   "token",
		httpclient: &http.Client{
			Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				return mockClient.Do(req)
			}),
		},
	}

	response := &http.Response{
		StatusCode: http.StatusCreated,
		Body:       io.NopCloser(bytes.NewBufferString(`{"issuer":"issuer1","domain":"domain1","cert":"cert-value","ca_issuer":"ca-issuer-value"}`)),
	}

	mockClient.On("Do", mock.Anything).Return(response, nil)

	certData := api.CertificateParams{Issuer: "issuer1", Domain: "domain1"}
	certificate, err := client.CreateCertificate(certData)
	assert.NoError(t, err)
	assert.Equal(t, "cert-value", certificate.Cert)
	assert.Equal(t, "ca-issuer-value", certificate.CAIssuer)
}

func TestUpdateCertificate(t *testing.T) {
	mockClient := &MockHTTPClient{}
	client := &Client{
		BaseURL: "http://example.com",
		Token:   "token",
		httpclient: &http.Client{
			Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				return mockClient.Do(req)
			}),
		},
	}

	response := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBufferString(`{"issuer":"issuer1","domain":"domain1","cert":"cert-value","ca_issuer":"ca-issuer-value"}`)),
	}

	mockClient.On("Do", mock.Anything).Return(response, nil)

	certData := api.CertificateParams{Issuer: "issuer1", Domain: "domain1"}
	certificate, err := client.UpdateCertificate(certData)
	assert.NoError(t, err)
	assert.Equal(t, "cert-value", certificate.Cert)
	assert.Equal(t, "ca-issuer-value", certificate.CAIssuer)
}

func TestDeleteCertificate(t *testing.T) {
	mockClient := &MockHTTPClient{}
	client := &Client{
		BaseURL: "http://example.com",
		Token:   "token",
		httpclient: &http.Client{
			Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				return mockClient.Do(req)
			}),
		},
	}

	response := &http.Response{
		StatusCode: http.StatusNoContent,
		Body:       io.NopCloser(bytes.NewBufferString(``)),
	}

	mockClient.On("Do", mock.Anything).Return(response, nil)

	err := client.DeleteCertificate("issuer1", "domain1", false)
	assert.NoError(t, err)
}

// roundTripperFunc is a helper function to create an http.RoundTripper from a function
type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
