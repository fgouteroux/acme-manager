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
	"github.com/sirupsen/logrus"

	"github.com/fgouteroux/acme-manager/models"
	"github.com/fgouteroux/acme-manager/utils"
)

// RetryConfig controls the retryablehttp client behaviour.
type RetryConfig struct {
	RetryMax        int
	RetryWaitMin    int // seconds
	RetryWaitMax    int // seconds
	RetryStatusCode []int
	Debug           bool
}

type Client struct {
	BaseURL    string
	Logger     *logrus.Logger
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

func NewClient(baseURL, token, certFile, keyFile, caFile string, insecure bool, logger *logrus.Logger, retryCfg RetryConfig) (*Client, error) {
	var client Client
	retryClient := retryablehttp.NewClient()

	retryClient.RetryMax = 4
	if retryCfg.RetryMax != 0 {
		retryClient.RetryMax = retryCfg.RetryMax
	}
	retryClient.RetryWaitMin = 1 * time.Second
	if retryCfg.RetryWaitMin != 0 {
		retryClient.RetryWaitMin = time.Duration(retryCfg.RetryWaitMin) * time.Second
	}
	retryClient.RetryWaitMax = 30 * time.Second
	if retryCfg.RetryWaitMax != 0 {
		retryClient.RetryWaitMax = time.Duration(retryCfg.RetryWaitMax) * time.Second
	}

	if logger != nil {
		retryClient.Logger = logger
		if retryCfg.Debug {
			retryClient.RequestLogHook = utils.RequestLogHook(logger)
			retryClient.ResponseLogHook = utils.ResponseLogHookDebug(logger)
		} else {
			retryClient.ResponseLogHook = utils.ResponseLogHook(logger, true)
		}
	} else {
		retryClient.Logger = nil
	}

	if len(retryCfg.RetryStatusCode) > 0 {
		retryClient.CheckRetry = newStatusCodeRetryPolicy(retryCfg.RetryStatusCode)
	}

	tlsConfig, err := setTLSConfig(certFile, keyFile, caFile, insecure)
	if err != nil {
		return &client, err
	}

	retryClient.HTTPClient.Transport = &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client.BaseURL = baseURL
	client.Logger = logger
	client.Token = token
	client.httpclient = retryClient.StandardClient()

	return &client, nil
}

func newStatusCodeRetryPolicy(retryStatusCodes []int) retryablehttp.CheckRetry {
	return func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		shouldRetry, defaultErr := retryablehttp.DefaultRetryPolicy(ctx, resp, err)
		if shouldRetry || defaultErr != nil {
			return shouldRetry, defaultErr
		}
		if resp != nil {
			for _, code := range retryStatusCodes {
				if resp.StatusCode == code {
					return true, nil
				}
			}
		}
		return false, nil
	}
}

func (c *Client) doRequest(ctx context.Context, method, path string, headers map[string]string, body io.Reader, timeout int) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return nil, err
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := c.httpclient.Do(req)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			if _, ok := ctx.Deadline(); ok {
				// Calculate total timeout duration in seconds
				timeoutDuration := time.Duration(timeout) * time.Second
				err = fmt.Errorf("%w: Timeout duration was %d seconds", err, timeoutDuration/time.Second)
			}
		}
		return nil, err
	}

	return resp, nil
}

func (c *Client) decodeJSON(resp *http.Response, v interface{}) error {
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(v)
}

func (c *Client) GetAllCertificateMetadata(timeout int) ([]models.Certificate, error) {
	var certificate []models.Certificate
	headers := make(map[string]string, 1)
	headers["Authorization"] = "Bearer " + c.Token

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	baseErrMsg := "error getting all certificate metadata"

	resp, err := c.doRequest(ctx, "GET", "/certificate/metadata", headers, nil, timeout)
	if err != nil {
		return certificate, fmt.Errorf("%s - %w", baseErrMsg, err)
	}

	if resp.StatusCode != http.StatusOK {
		return certificate, fmt.Errorf("%s: %s", baseErrMsg, resp.Status)
	}

	if err := c.decodeJSON(resp, &certificate); err != nil {
		return certificate, fmt.Errorf("%s - %w", baseErrMsg, err)
	}

	return certificate, nil
}

func (c *Client) GetCertificateMetadata(issuer, domain, name string, timeout int) (models.Certificate, error) {
	var certificate models.Certificate
	headers := make(map[string]string, 1)
	headers["Authorization"] = "Bearer " + c.Token

	if issuer == "" && domain == "" {
		return certificate, fmt.Errorf("missing or empty 'issuer' and 'domain' query parameters")
	}

	path := fmt.Sprintf("/certificate/metadata?issuer=%s&domain=%s", issuer, domain)
	if name != "" {
		path += "&name=" + name
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	baseErrMsg := "error getting certificate metadata"

	resp, err := c.doRequest(ctx, "GET", path, headers, nil, timeout)
	if err != nil {
		return certificate, fmt.Errorf("%s - %w", baseErrMsg, err)
	}

	if resp.StatusCode != http.StatusOK {
		return certificate, fmt.Errorf("%s: %s", baseErrMsg, resp.Status)
	}

	if err := c.decodeJSON(resp, &certificate); err != nil {
		return certificate, fmt.Errorf("%s - %w", baseErrMsg, err)
	}

	return certificate, nil
}

func (c *Client) ReadCertificate(data models.Certificate, timeout int) (models.CertMap, error) {
	var certificate models.CertMap
	headers := make(map[string]string, 1)
	headers["Authorization"] = "Bearer " + c.Token

	reqBody, err := json.Marshal(data)
	if err != nil {
		return certificate, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	var readPath string
	var baseErrMsg string
	if data.Name != "" {
		readPath = fmt.Sprintf("/certificate/%s", data.Name)
		baseErrMsg = fmt.Sprintf("error reading certificate with name '%s':", data.Name)
	} else {
		readPath = fmt.Sprintf("/certificate/%s/%s", data.Issuer, data.Domain)
		baseErrMsg = fmt.Sprintf("error reading certificate with issuer '%s' and domain '%s':", data.Issuer, data.Domain)
	}
	resp, err := c.doRequest(ctx, "GET", readPath, headers, bytes.NewReader(reqBody), timeout)
	if err != nil {
		return certificate, fmt.Errorf("%s - %w", baseErrMsg, err)
	}

	if resp.StatusCode != http.StatusOK {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return certificate, fmt.Errorf("%s: %s", baseErrMsg, resp.Status)
		}
		return certificate, fmt.Errorf("%s: %s - %s", baseErrMsg, resp.Status, string(respBody))
	}

	if err := c.decodeJSON(resp, &certificate); err != nil {
		return certificate, fmt.Errorf("%s - %w", baseErrMsg, err)
	}

	return certificate, nil
}

func (c *Client) CreateCertificate(data models.CertificateParams, timeout int) (models.CertMap, error) {
	var certificate models.CertMap
	headers := make(map[string]string, 1)
	headers["Authorization"] = "Bearer " + c.Token

	reqBody, err := json.Marshal(data)
	if err != nil {
		return certificate, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	resp, err := c.doRequest(ctx, "POST", "/certificate", headers, bytes.NewReader(reqBody), timeout)
	if err != nil {
		return certificate, err
	}

	if resp.StatusCode != http.StatusCreated {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return certificate, fmt.Errorf("%s - %w", resp.Status, err)
		}
		return certificate, fmt.Errorf("%s - %s", resp.Status, string(respBody))
	}

	if err := c.decodeJSON(resp, &certificate); err != nil {
		return certificate, err
	}

	return certificate, nil
}

func (c *Client) UpdateCertificate(data models.CertificateParams, timeout int) (models.CertMap, error) {
	var certificate models.CertMap
	headers := make(map[string]string, 1)
	headers["Authorization"] = "Bearer " + c.Token

	reqBody, err := json.Marshal(data)
	if err != nil {
		return certificate, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	resp, err := c.doRequest(ctx, "PUT", "/certificate", headers, bytes.NewReader(reqBody), timeout)
	if err != nil {
		return certificate, err
	}

	if resp.StatusCode != http.StatusOK {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return certificate, fmt.Errorf("%s - %w", resp.Status, err)
		}
		return certificate, fmt.Errorf("%s - %s", resp.Status, string(respBody))
	}

	if err := c.decodeJSON(resp, &certificate); err != nil {
		return certificate, err
	}

	return certificate, nil
}

func (c *Client) DeleteCertificate(issuer, domain, name string, revoke bool, timeout int) error {
	headers := make(map[string]string, 1)
	headers["Authorization"] = "Bearer " + c.Token

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	var deletePath string
	if name != "" {
		deletePath = fmt.Sprintf("/certificate/%s?revoke=%v", name, revoke)
	} else {
		deletePath = fmt.Sprintf("/certificate/%s/%s?revoke=%v", issuer, domain, revoke)
	}
	resp, err := c.doRequest(ctx, "DELETE", deletePath, headers, nil, timeout)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusNoContent {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("%s - %w", resp.Status, err)
		}
		return fmt.Errorf("%s - %s", resp.Status, string(respBody))
	}

	return nil
}

func (c *Client) GetSelfToken(timeout int) (models.Token, error) {
	var token models.Token
	headers := make(map[string]string, 1)
	headers["Authorization"] = "Bearer " + c.Token

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	baseErrMsg := "error getting self token"

	resp, err := c.doRequest(ctx, "GET", "/token/self", headers, nil, timeout)
	if err != nil {
		return token, fmt.Errorf("%s - %v", baseErrMsg, err)
	}

	if resp.StatusCode != http.StatusOK {
		return token, fmt.Errorf("%s: %s", baseErrMsg, resp.Status)
	}

	if err := c.decodeJSON(resp, &token); err != nil {
		return token, fmt.Errorf("%s - %v", baseErrMsg, err)
	}

	return token, nil
}
