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
	"time"

	"github.com/hashicorp/go-retryablehttp"

	cert "github.com/fgouteroux/acme_manager/certificate"
)

type Client struct {
	BaseURL    string
	Token      string
	httpclient *http.Client
}

func setTLSConfig(cert string, key string, ca string, insecure bool) (*tls.Config, error) {
	tlsConfig := &tls.Config{}

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
		caCert, err := os.ReadFile(ca)
		if err != nil {
			return tlsConfig, err
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
	}
	return tlsConfig, nil
}

func NewClient(baseURL, token, caFile, certFile, keyFile string, insecure bool) (*Client, error) {
	var client Client
	retryClient := retryablehttp.NewClient()
	retryClient.Logger = nil

	tlsConfig, err := setTLSConfig(caFile, certFile, keyFile, insecure)
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

func (c *Client) GetAllCertificateMetadata() ([]cert.Certificate, error) {
	var certificate []cert.Certificate
	headers := make(map[string]string, 1)
	headers["Authorization"] = "Bearer " + c.Token

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	resp, err := c.doRequest(ctx, "GET", "/certificate/metadata", headers, nil)
	if err != nil {
		return certificate, err
	}

	if resp.StatusCode != http.StatusOK {
		return certificate, fmt.Errorf("error getting all certificate metadata: %s", resp.Status)
	}

	if err := c.decodeJSON(resp, &certificate); err != nil {
		return certificate, err
	}

	return certificate, nil
}

func (c *Client) GetCertificateMetadata(issuer, domain string) (cert.Certificate, error) {
	var certificate cert.Certificate
	headers := make(map[string]string, 1)
	headers["Authorization"] = "Bearer " + c.Token

	if issuer != "" && domain != "" {
		return certificate, fmt.Errorf("missing or empty 'issuer' and 'domain' query parameters")
	}

	path := fmt.Sprintf("/certificate/metadata?issuer=%s&domain=%s", issuer, domain)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := c.doRequest(ctx, "GET", path, headers, nil)
	if err != nil {
		return certificate, err
	}

	if resp.StatusCode != http.StatusOK {
		return certificate, fmt.Errorf("error getting certificate metadata: %s", resp.Status)
	}

	if err := c.decodeJSON(resp, &certificate); err != nil {
		return certificate, err
	}

	return certificate, nil
}

func (c *Client) ReadCertificate(data cert.Certificate) (map[string]interface{}, error) {
	headers := make(map[string]string, 1)
	headers["Authorization"] = "Bearer " + c.Token

	reqBody, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := c.doRequest(ctx, "GET", "/certificate", headers, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("error reading certificate with issuer '%s' and domain '%s': %s - %s", data.Issuer, data.Domain, resp.Status, string(respBody))
	}

	var certificate map[string]interface{}
	if err := c.decodeJSON(resp, &certificate); err != nil {
		return nil, err
	}

	return certificate, nil
}

func (c *Client) CreateCertificate(data cert.Certificate) (map[string]interface{}, error) {
	headers := make(map[string]string, 1)
	headers["Authorization"] = "Bearer " + c.Token

	reqBody, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	resp, err := c.doRequest(ctx, "POST", "/certificate", headers, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("error creating certificate with issuer '%s' and domain '%s': %s - %s", data.Issuer, data.Domain, resp.Status, string(respBody))
	}

	var certificate map[string]interface{}
	if err := c.decodeJSON(resp, &certificate); err != nil {
		return nil, err
	}

	return certificate, nil
}

func (c *Client) UpdateCertificate(data cert.Certificate) (map[string]interface{}, error) {
	headers := make(map[string]string, 1)
	headers["Authorization"] = "Bearer " + c.Token

	reqBody, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	resp, err := c.doRequest(ctx, "PUT", "/certificate", headers, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("error updating certificate with issuer '%s' and domain '%s': %s - %s", data.Issuer, data.Domain, resp.Status, string(respBody))
	}

	var certificate map[string]interface{}
	if err := c.decodeJSON(resp, &certificate); err != nil {
		return nil, err
	}

	return certificate, nil
}

func (c *Client) DeleteCertificate(data cert.Certificate) (string, error) {
	headers := make(map[string]string, 1)
	headers["Authorization"] = "Bearer " + c.Token

	reqBody, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := c.doRequest(ctx, "DELETE", "/certificate", headers, bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		return "", fmt.Errorf("error deleting certificate with issuer '%s' and domain '%s': %s - %s", data.Issuer, data.Domain, resp.Status, string(respBody))
	}

	var result []byte
	result, err = io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(result), nil
}
