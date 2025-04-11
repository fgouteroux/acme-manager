package restclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/hashicorp/go-retryablehttp"

	"github.com/fgouteroux/acme_manager/api"
	"github.com/fgouteroux/acme_manager/certstore"
)

type Client struct {
	BaseURL    string
	Token      string
	httpclient *http.Client
}

func setTLSConfig(cert string, key string, ca string, insecure bool) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}

	if insecure {
		tlsConfig.InsecureSkipVerify = insecure
		return tlsConfig, nil
	}

	if cert != "" && key != "" {
		// Load client cert
		certificate, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return tlsConfig, err
		}

		tlsConfig.Certificates = []tls.Certificate{certificate}
	}

	if ca != "" {
		// Load CA cert
		caCert, err := os.ReadFile(filepath.Clean(ca))
		if err != nil {
			return tlsConfig, err
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
	}
	return tlsConfig, nil
}

func NewClient(baseURL, token, certFile, keyFile, caFile string, insecure bool) (*Client, error) {
	var client Client
	retryClient := retryablehttp.NewClient()
	retryClient.Logger = nil

	tlsConfig, err := setTLSConfig(certFile, keyFile, caFile, insecure)
	if err != nil {
		return &client, err
	}

	retryClient.HTTPClient.Transport = &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client.BaseURL = baseURL
	client.Token = token
	client.httpclient = retryClient.StandardClient()

	return &client, nil
}

func (c *Client) doRequest(ctx context.Context, method, path string, headers map[string]string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return nil, err
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := c.httpclient.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *Client) decodeJSON(resp *http.Response, v interface{}) error {
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(v)
}

func (c *Client) GetAllCertificateMetadata() ([]certstore.Certificate, error) {
	var certificate []certstore.Certificate
	headers := make(map[string]string, 1)
	headers["Authorization"] = "Bearer " + c.Token

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	baseErrMsg := "error getting all certificate metadata"

	resp, err := c.doRequest(ctx, "GET", "/certificate/metadata", headers, nil)
	if err != nil {
		return certificate, fmt.Errorf("%s - %v", baseErrMsg, err)
	}

	if resp.StatusCode != http.StatusOK {
		return certificate, fmt.Errorf("%s: %s - %v", baseErrMsg, resp.Status, err)
	}

	if err := c.decodeJSON(resp, &certificate); err != nil {
		return certificate, fmt.Errorf("%s - %v", baseErrMsg, err)
	}

	return certificate, nil
}

func (c *Client) GetCertificateMetadata(issuer, domain string) (certstore.Certificate, error) {
	var certificate certstore.Certificate
	headers := make(map[string]string, 1)
	headers["Authorization"] = "Bearer " + c.Token

	if issuer == "" && domain == "" {
		return certificate, fmt.Errorf("missing or empty 'issuer' and 'domain' query parameters")
	}

	path := fmt.Sprintf("/certificate/metadata?issuer=%s&domain=%s", issuer, domain)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	baseErrMsg := "error getting certificate metadata"

	resp, err := c.doRequest(ctx, "GET", path, headers, nil)
	if err != nil {
		return certificate, fmt.Errorf("%s - %v", baseErrMsg, err)
	}

	if resp.StatusCode != http.StatusOK {
		return certificate, fmt.Errorf("%s: %s - %v", baseErrMsg, resp.Status, err)
	}

	if err := c.decodeJSON(resp, &certificate); err != nil {
		return certificate, fmt.Errorf("%s - %v", baseErrMsg, err)
	}

	return certificate, nil
}

func (c *Client) ReadCertificate(data certstore.Certificate) (certstore.CertMap, error) {
	var certificate certstore.CertMap
	headers := make(map[string]string, 1)
	headers["Authorization"] = "Bearer " + c.Token

	reqBody, err := json.Marshal(data)
	if err != nil {
		return certificate, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	baseErrMsg := fmt.Sprintf("error reading certificate with issuer '%s' and domain '%s':", data.Issuer, data.Domain)

	resp, err := c.doRequest(ctx, "GET", fmt.Sprintf("/certificate/%s/%s", data.Issuer, data.Domain), headers, bytes.NewReader(reqBody))
	if err != nil {
		return certificate, fmt.Errorf("%s - %v", baseErrMsg, err)
	}

	if resp.StatusCode != http.StatusOK {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return certificate, fmt.Errorf("%s: %s - %v", baseErrMsg, resp.Status, err)
		}
		return certificate, fmt.Errorf("%s: %s - %s", baseErrMsg, resp.Status, string(respBody))
	}

	if err := c.decodeJSON(resp, &certificate); err != nil {
		return certificate, fmt.Errorf("%s - %v", baseErrMsg, err)
	}

	return certificate, nil
}

func (c *Client) CreateCertificate(data api.CertificateParams) (certstore.CertMap, error) {
	var certificate certstore.CertMap
	headers := make(map[string]string, 1)
	headers["Authorization"] = "Bearer " + c.Token

	reqBody, err := json.Marshal(data)
	if err != nil {
		return certificate, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	baseErrMsg := fmt.Sprintf("error creating certificate with issuer '%s' and domain '%s':", data.Issuer, data.Domain)

	resp, err := c.doRequest(ctx, "POST", "/certificate", headers, bytes.NewReader(reqBody))
	if err != nil {
		return certificate, fmt.Errorf("%s - %v", baseErrMsg, err)
	}

	if resp.StatusCode != http.StatusCreated {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return certificate, fmt.Errorf("%s: %s - %v", baseErrMsg, resp.Status, err)
		}
		return certificate, fmt.Errorf("%s: %s - %s", baseErrMsg, resp.Status, string(respBody))
	}

	if err := c.decodeJSON(resp, &certificate); err != nil {
		return certificate, fmt.Errorf("%s - %v", baseErrMsg, err)
	}

	return certificate, nil
}

func (c *Client) UpdateCertificate(data api.CertificateParams) (certstore.CertMap, error) {
	var certificate certstore.CertMap
	headers := make(map[string]string, 1)
	headers["Authorization"] = "Bearer " + c.Token

	reqBody, err := json.Marshal(data)
	if err != nil {
		return certificate, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	baseErrMsg := fmt.Sprintf("error updating certificate with issuer '%s' and domain '%s':", data.Issuer, data.Domain)

	resp, err := c.doRequest(ctx, "PUT", "/certificate", headers, bytes.NewReader(reqBody))
	if err != nil {
		return certificate, fmt.Errorf("%s - %v", baseErrMsg, err)
	}

	if resp.StatusCode != http.StatusOK {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return certificate, fmt.Errorf("%s: %s - %v", baseErrMsg, resp.Status, err)
		}
		return certificate, fmt.Errorf("%s: %s - %s", baseErrMsg, resp.Status, string(respBody))
	}

	if err := c.decodeJSON(resp, &certificate); err != nil {
		return certificate, fmt.Errorf("%s - %v", baseErrMsg, err)
	}

	return certificate, nil
}

func (c *Client) DeleteCertificate(issuer, domain string, revoke bool) error {
	headers := make(map[string]string, 1)
	headers["Authorization"] = "Bearer " + c.Token

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	baseErrMsg := fmt.Sprintf("error deleting certificate with issuer '%s' and domain '%s':", issuer, domain)

	resp, err := c.doRequest(ctx, "DELETE", fmt.Sprintf("/certificate/%s/%s?revoke=%v", issuer, domain, revoke), headers, nil)
	if err != nil {
		return fmt.Errorf("%s - %v", baseErrMsg, err)
	}

	if resp.StatusCode != http.StatusNoContent {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("%s: %s - %v", baseErrMsg, resp.Status, err)
		}
		return fmt.Errorf("%s: %s - %s", baseErrMsg, resp.Status, string(respBody))
	}

	return nil
}

func (c *Client) GetSelfToken() (certstore.Token, error) {
	var token certstore.Token
	headers := make(map[string]string, 1)
	headers["Authorization"] = "Bearer " + c.Token

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	baseErrMsg := "error getting self token"

	resp, err := c.doRequest(ctx, "GET", "/token/self", headers, nil)
	if err != nil {
		return token, fmt.Errorf("%s - %v", baseErrMsg, err)
	}

	if resp.StatusCode != http.StatusOK {
		return token, fmt.Errorf("%s: %s - %v", baseErrMsg, resp.Status, err)
	}

	if err := c.decodeJSON(resp, &token); err != nil {
		return token, fmt.Errorf("%s - %v", baseErrMsg, err)
	}

	return token, nil
}
