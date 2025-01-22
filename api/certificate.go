package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/go-acme/lego/v4/certcrypto"

	"github.com/fgouteroux/acme_manager/certstore"
	"github.com/fgouteroux/acme_manager/config"
	"github.com/fgouteroux/acme_manager/metrics"
	"github.com/fgouteroux/acme_manager/ring"
	"github.com/fgouteroux/acme_manager/storage/vault"
	"github.com/fgouteroux/acme_manager/utils"
)

var certLockMap sync.Map

// responseErrorJSON example
type responseErrorJSON struct {
	Error string `json:"error" example:"error"`
}

// used only for swagger
type CertificateParams struct {
	Domain        string `json:"domain" example:"testfgx.example.com"`
	Issuer        string `json:"issuer" example:"letsencrypt"`
	Bundle        bool   `json:"bundle" example:"false"`
	SAN           string `json:"san,omitempty" example:""`
	CSR           string `json:"csr,omitempty"`
	Days          int    `json:"days,omitempty" example:"90"`
	RenewalDays   int    `json:"renewal_days,omitempty" example:"30"`
	DNSChallenge  string `json:"dns_challenge,omitempty" example:"ns1"`
	HTTPChallenge string `json:"http_challenge,omitempty" example:""`
}

func responseJSON(w http.ResponseWriter, data interface{}, err error, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		output, _ := json.Marshal(&responseErrorJSON{Error: err.Error()})
		http.Error(w, string(output), statusCode)
	} else {
		output, _ := json.Marshal(data)
		w.WriteHeader(statusCode)
		_, _ = w.Write(output)
	}
}

func checkAuth(r *http.Request) (certstore.Token, error) {
	var tokenData certstore.Token
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return tokenData, fmt.Errorf("Authorization Header is missing or empty")
	}
	splitToken := strings.Split(authHeader, "Bearer ")
	if len(splitToken) != 2 {
		return tokenData, fmt.Errorf("Invalid token format")
	}

	payload, err := base64.StdEncoding.DecodeString(splitToken[1])
	if err != nil {
		return tokenData, fmt.Errorf("Invalid token format")
	}

	token := strings.SplitN(string(payload), ":", 2)
	if len(token) != 2 {
		return tokenData, fmt.Errorf("Invalid token format")
	}

	tokens, err := certstore.AmStore.GetKVRingToken(certstore.TokenRingKey)
	if err != nil {
		return tokenData, err
	}

	var tokenExists bool
	tokenData, tokenExists = tokens[token[0]]
	if !tokenExists {
		return tokenData, fmt.Errorf("Token not found")
	}

	reqTokenHash := utils.SHA1Hash(token[1])
	if tokenExists && reqTokenHash != tokenData.TokenHash {
		return tokenData, fmt.Errorf("Invalid token")
	}

	if tokenData.Expires != "Never" {
		layout := "2006-01-02 15:04:05 -0700 MST"
		t, err := time.Parse(layout, tokenData.Expires)
		if err != nil {
			return tokenData, fmt.Errorf("Could not parse token expiration time")
		}

		if time.Now().After(t) {
			return tokenData, fmt.Errorf("Token expired")
		}
	}

	return tokenData, nil
}

// manage metadata certificate

// certificateMetadata godoc
// @Summary Read metadata certificate
// @Description Return certificate metadata like SAN,expiration, fingerprint...
// @Tags metadata certificate
// @Produce  application/json
// @Param Authorization header string true "Access token" default(Bearer <Add access token here>)
// @Param issuer query string false "Certificate issuer" default(letsencrypt)
// @Param domain query string false "Certificate domain" default(testfgx.example.com)
// @Success 200 {object} []certstore.Certificate
// @Success 404 {object} responseErrorJSON
// @Success 500 {object} responseErrorJSON
// @Router /certificate/metadata [get]
func CertificateMetadataHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		tokenValue, err := checkAuth(r)
		if err != nil {
			responseJSON(w, nil, err, http.StatusUnauthorized)
			return
		}

		w.Header().Set("Username", tokenValue.Username)

		data, err := certstore.AmStore.GetKVRingCert(certstore.AmRingKey)
		if err != nil {
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}

		issuer := r.URL.Query().Get("issuer")
		domain := r.URL.Query().Get("domain")

		var metadata []certstore.Certificate
		if issuer != "" && domain != "" {
			idx := slices.IndexFunc(data, func(c certstore.Certificate) bool {
				return c.Domain == domain && c.Issuer == issuer && c.Owner == tokenValue.Username
			})
			if idx == -1 {
				responseJSON(w, nil, fmt.Errorf("Certificate '%s' with issuer '%s' not found", domain, issuer), http.StatusNotFound)
				return
			}
			metadata = append(metadata, data[idx])
		} else {
			for _, item := range data {

				if item.Owner == tokenValue.Username {
					metadata = append(metadata, item)
				}
			}
		}
		responseJSON(w, metadata, nil, http.StatusOK)
	})
}

// manage certificate

// certificate godoc
// @Summary Read certificate
// @Description Return certificate and issuer ca certificate.
// @Tags certificate
// @Produce  application/json
// @Param Authorization header string true "Access token" default(Bearer <Add access token here>)
// @Param issuer path string true "Certificate issuer" default(letsencrypt)
// @Param domain path string true "Certificate domain" default(testfgx.example.com)
// @Success 200 {object} certstore.CertMap
// @Success 400 {object} responseErrorJSON
// @Success 401 {object} responseErrorJSON
// @Success 403 {object} responseErrorJSON
// @Success 404 {object} responseErrorJSON
// @Success 500 {object} responseErrorJSON
// @Router /certificate/{issuer}/{domain} [get]
func GetCertificateHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenValue, err := checkAuth(r)
		if err != nil {
			responseJSON(w, nil, err, http.StatusUnauthorized)
			return
		}

		w.Header().Set("Username", tokenValue.Username)

		certData := &certstore.Certificate{
			Domain: r.PathValue("domain"),
			Issuer: r.PathValue("issuer"),
			Owner:  tokenValue.Username,
		}

		if certData.Domain == "" || certData.Issuer == "" {
			responseJSON(w, nil, fmt.Errorf("missing 'issuer' and/or 'domain' parameter"), http.StatusBadRequest)
			return
		}

		data, err := certstore.AmStore.GetKVRingCert(certstore.AmRingKey)
		if err != nil {
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}

		idx := slices.IndexFunc(data, func(c certstore.Certificate) bool {
			return c.Domain == certData.Domain && c.Issuer == certData.Issuer && c.Owner == certData.Owner
		})

		var owner string
		if idx != -1 {
			owner = data[idx].Owner
		}

		if !slices.Contains(tokenValue.Scope, "read") {
			responseJSON(w, nil, fmt.Errorf("Invalid scope, missing 'read' scope"), http.StatusForbidden)
			return
		}
		if idx == -1 || certData.Owner != owner {
			responseJSON(w, nil, fmt.Errorf("Certificate '%s' with issuer '%s' not found", certData.Domain, certData.Issuer), http.StatusNotFound)
			return
		}
		secretKeyPath := fmt.Sprintf("%s/%s/%s", config.GlobalConfig.Storage.Vault.CertPrefix, certData.Issuer, certData.Domain)
		secret, err := vault.GlobalClient.GetSecretWithAppRole(secretKeyPath)
		if err != nil {
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}

		responseJSON(w, certstore.MapInterfaceToCertMap(secret), nil, http.StatusOK)
	})
}

// manage certificate

// certificate godoc
// @Summary Create certificate
// @Description Create certificate for a given issuer and domain name.
// @Tags certificate
// @Produce  application/json
// @Param Authorization header string true "Access token" default(Bearer <Add access token here>)
// @Param body body CertificateParams true "Certificate body"
// @Success 201 {object} certstore.CertMap
// @Success 400 {object} responseErrorJSON
// @Success 401 {object} responseErrorJSON
// @Success 403 {object} responseErrorJSON
// @Success 429 {object} responseErrorJSON
// @Success 500 {object} responseErrorJSON
// @Success 502 {object} responseErrorJSON
// @Router /certificate [post]
func CreateCertificateHandler(logger log.Logger, proxyClient *http.Client) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenValue, err := checkAuth(r)
		if err != nil {
			responseJSON(w, nil, err, http.StatusUnauthorized)
			return
		}

		w.Header().Set("Username", tokenValue.Username)

		// validate the request body
		var certParams CertificateParams
		err = json.NewDecoder(r.Body).Decode(&certParams)
		if err != nil {
			responseJSON(w, nil, err, http.StatusBadRequest)
			return
		}

		if certParams.Domain == "" || certParams.Issuer == "" {
			responseJSON(w, nil, fmt.Errorf("missing 'issuer' and/or 'domain' parameter"), http.StatusBadRequest)
			return
		}

		if !slices.Contains(config.SupportedIssuers, certParams.Issuer) {
			responseJSON(w, nil, fmt.Errorf("Invalid issuer '%s' must be one of %v", certParams.Issuer, config.SupportedIssuers), http.StatusBadRequest)
			return
		}

		if certParams.Days != 0 && certParams.RenewalDays >= certParams.Days {
			responseJSON(w, nil, fmt.Errorf("'renewal_days' (%d) should be lower than 'days' (%d)", certParams.RenewalDays, certParams.Days), http.StatusBadRequest)
			return
		}

		if certParams.DNSChallenge != "" && certParams.HTTPChallenge != "" {
			responseJSON(w, nil, fmt.Errorf("'dns_challenge' and 'http_challenge' are mutually exclusive"), http.StatusBadRequest)
			return
		}

		err = checkCSR(certParams)
		if err != nil {
			responseJSON(w, nil, err, http.StatusBadRequest)
			return
		}

		// convert request params to certificate object
		certBytes, _ := json.Marshal(certParams)
		var certData certstore.Certificate
		err = json.Unmarshal(certBytes, &certData)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}

		certData.Owner = tokenValue.Username

		data, err := certstore.AmStore.GetKVRingCert(certstore.AmRingKey)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}

		idx := slices.IndexFunc(data, func(c certstore.Certificate) bool {
			return c.Domain == certData.Domain && c.Issuer == certData.Issuer && c.Owner == certData.Owner
		})

		if idx >= 0 {
			responseJSON(w, nil, fmt.Errorf("Certificate already exists"), http.StatusBadRequest)
			return
		}

		isLeaderNow, err := ring.IsLeader(certstore.AmStore.RingConfig)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}
		if !isLeaderNow {
			host, _ := ring.GetLeaderIP(certstore.AmStore.RingConfig)
			_ = level.Info(logger).Log("msg", fmt.Sprintf("Forwarding '%s' request to '%s'", r.Method, host))
			body, _ := json.Marshal(certData)
			r.Body = io.NopCloser(bytes.NewReader(body))
			forwardRequest(proxyClient, host, w, r)
			return
		}

		// no concurrent task for the same certificate here
		certLockKey := certData.Issuer + "/" + certData.Domain

		_, locked := certLockMap.Load(certLockKey)
		if locked {
			responseJSON(w, nil, fmt.Errorf("Another operation is in progress"), http.StatusTooManyRequests)
			return
		}

		certLockMap.Store(certLockKey, r.Method)
		_ = level.Debug(logger).Log("msg", fmt.Sprintf("Locking operation for key '%s' on '%s' method", certLockKey, r.Method))
		defer func() { certLockMap.Delete(certLockKey) }() // Unlock deferred

		if !slices.Contains(tokenValue.Scope, "create") {
			responseJSON(w, nil, fmt.Errorf("Invalid scope, missing 'create' scope"), http.StatusForbidden)
			return
		}

		newCert, err := certstore.CreateRemoteCertificateResource(certData, certstore.AmStore.Logger)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			statusCode := http.StatusInternalServerError
			if strings.Contains(err.Error(), "urn:ietf:params:acme:error:malformed") {
				statusCode = http.StatusBadRequest
			}

			responseJSON(w, nil, err, statusCode)
			return
		}
		metrics.IncManagedCertificate(certData.Issuer, certData.Owner)
		data = append(data, newCert)

		// udpate kv store
		certstore.AmStore.PutKVRing(certstore.AmRingKey, data)

		secretKeyPath := fmt.Sprintf("%s/%s/%s", config.GlobalConfig.Storage.Vault.CertPrefix, certData.Issuer, certData.Domain)
		secret, err := vault.GlobalClient.GetSecretWithAppRole(secretKeyPath)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}

		responseJSON(w, certstore.MapInterfaceToCertMap(secret), nil, http.StatusCreated)
	})
}

// manage certificate

// certificate godoc
// @Summary Update certificate
// @Description Update certificate will revoke the old and create a new certificate with given parameters.
// @Tags certificate
// @Produce  application/json
// @Param Authorization header string true "Access token" default(Bearer <Add access token here>)
// @Param body body CertificateParams true "Certificate body"
// @Success 200 {object} certstore.CertMap
// @Success 400 {object} responseErrorJSON
// @Success 401 {object} responseErrorJSON
// @Success 403 {object} responseErrorJSON
// @Success 404 {object} responseErrorJSON
// @Success 429 {object} responseErrorJSON
// @Success 500 {object} responseErrorJSON
// @Success 502 {object} responseErrorJSON
// @Router /certificate [put]
func UpdateCertificateHandler(logger log.Logger, proxyClient *http.Client) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenValue, err := checkAuth(r)
		if err != nil {
			responseJSON(w, nil, err, http.StatusUnauthorized)
			return
		}

		w.Header().Set("Username", tokenValue.Username)

		// validate the request body
		var certParams CertificateParams
		err = json.NewDecoder(r.Body).Decode(&certParams)
		if err != nil {
			responseJSON(w, nil, err, http.StatusBadRequest)
			return
		}

		if certParams.Domain == "" || certParams.Issuer == "" {
			responseJSON(w, nil, fmt.Errorf("missing 'issuer' and/or 'domain' parameter"), http.StatusBadRequest)
			return
		}

		if !slices.Contains(config.SupportedIssuers, certParams.Issuer) {
			responseJSON(w, nil, fmt.Errorf("Invalid issuer '%s' must be one of %v", certParams.Issuer, config.SupportedIssuers), http.StatusBadRequest)
			return
		}

		if certParams.Days != 0 && certParams.RenewalDays >= certParams.Days {
			responseJSON(w, nil, fmt.Errorf("'renewal_days' (%d) should be lower than 'days' (%d)", certParams.RenewalDays, certParams.Days), http.StatusBadRequest)
			return
		}

		if certParams.DNSChallenge != "" && certParams.HTTPChallenge != "" {
			responseJSON(w, nil, fmt.Errorf("'dns_challenge' and 'http_challenge' are mutually exclusive"), http.StatusBadRequest)
			return
		}

		err = checkCSR(certParams)
		if err != nil {
			responseJSON(w, nil, err, http.StatusBadRequest)
			return
		}

		// convert request params to certificate object
		certBytes, _ := json.Marshal(certParams)
		var certData certstore.Certificate
		err = json.Unmarshal(certBytes, &certData)
		if err != nil {
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}

		certData.Owner = tokenValue.Username

		data, err := certstore.AmStore.GetKVRingCert(certstore.AmRingKey)
		if err != nil {
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}

		idx := slices.IndexFunc(data, func(c certstore.Certificate) bool {
			return c.Domain == certData.Domain && c.Issuer == certData.Issuer && c.Owner == certData.Owner
		})

		if idx == -1 {
			responseJSON(w, nil, fmt.Errorf("Certificate '%s' with issuer '%s' not found", certData.Domain, certData.Issuer), http.StatusNotFound)
			return
		}

		isLeaderNow, err := ring.IsLeader(certstore.AmStore.RingConfig)
		if err != nil {
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}
		if !isLeaderNow {
			host, _ := ring.GetLeaderIP(certstore.AmStore.RingConfig)
			_ = level.Info(logger).Log("msg", fmt.Sprintf("Forwarding '%s' request to '%s'", r.Method, host))
			body, _ := json.Marshal(certData)
			r.Body = io.NopCloser(bytes.NewReader(body))
			forwardRequest(proxyClient, host, w, r)
			return
		}

		// no concurrent task for the same certificate here
		certLockKey := certData.Issuer + "/" + certData.Domain

		_, locked := certLockMap.Load(certLockKey)
		if locked {
			responseJSON(w, nil, fmt.Errorf("Another operation is in progress"), http.StatusTooManyRequests)
			return
		}

		certLockMap.Store(certLockKey, r.Method)
		_ = level.Debug(logger).Log("msg", fmt.Sprintf("Locking operation for key '%s' on '%s' method", certLockKey, r.Method))
		defer func() { certLockMap.Delete(certLockKey) }() // Unlock deferred

		if !slices.Contains(tokenValue.Scope, "update") {
			responseJSON(w, nil, fmt.Errorf("Invalid scope, missing 'update' scope"), http.StatusForbidden)
			return
		}

		secretKeyPath := fmt.Sprintf("%s/%s/%s", config.GlobalConfig.Storage.Vault.CertPrefix, certData.Issuer, certData.Domain)

		var recreateCert bool
		if certData.SAN != data[idx].SAN {
			recreateCert = true
		}
		if certData.Days != data[idx].Days {
			recreateCert = true
		}
		if certData.Bundle != data[idx].Bundle {
			recreateCert = true
		}
		if certData.DNSChallenge != data[idx].DNSChallenge {
			recreateCert = true
		}
		if certData.HTTPChallenge != data[idx].HTTPChallenge {
			recreateCert = true
		}
		if certData.CSR != data[idx].CSR {
			recreateCert = true
		}

		if recreateCert {
			err = certstore.DeleteRemoteCertificateResource(certData, certstore.AmStore.Logger)
			if err != nil {
				responseJSON(w, nil, err, http.StatusInternalServerError)
				return
			}
			metrics.DecManagedCertificate(certData.Issuer, certData.Owner)

			data = slices.Delete(data, idx, idx+1)

			newCert, err := certstore.CreateRemoteCertificateResource(certData, certstore.AmStore.Logger)
			if err != nil {
				responseJSON(w, nil, err, http.StatusInternalServerError)
				return
			}
			metrics.IncManagedCertificate(certData.Issuer, certData.Owner)
			data = append(data, newCert)
		} else {
			data[idx].RenewalDays = certData.RenewalDays
			secret, err := vault.GlobalClient.GetSecretWithAppRole(secretKeyPath)
			if err != nil {
				responseJSON(w, nil, err, http.StatusInternalServerError)
				return
			}
			secret["renewal_days"] = certData.RenewalDays
			err = vault.GlobalClient.PutSecretWithAppRole(secretKeyPath, utils.StructToMapInterface(secret))
			if err != nil {
				responseJSON(w, nil, err, http.StatusInternalServerError)
				return
			}
			// udpate kv store
			certstore.AmStore.PutKVRing(certstore.AmRingKey, data)
			responseJSON(w, certstore.MapInterfaceToCertMap(secret), nil, http.StatusOK)
			return
		}

		// udpate kv store
		certstore.AmStore.PutKVRing(certstore.AmRingKey, data)

		secret, err := vault.GlobalClient.GetSecretWithAppRole(secretKeyPath)
		if err != nil {
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}

		responseJSON(w, certstore.MapInterfaceToCertMap(secret), nil, http.StatusOK)
	})
}

// manage certificate

// certificate godoc
// @Summary Revoke certificate
// @Description Revoke certificate for the given issuer and domain name.
// @Tags certificate
// @Produce  application/json
// @Param Authorization header string true "Access token" default(Bearer <Add access token here>)
// @Param issuer path string true "Certificate issuer" default(letsencrypt)
// @Param domain path string true "Certificate domain" default(testfgx.example.com)
// @Success 204
// @Success 400 {object} responseErrorJSON
// @Success 401 {object} responseErrorJSON
// @Success 403 {object} responseErrorJSON
// @Success 404 {object} responseErrorJSON
// @Success 429 {object} responseErrorJSON
// @Success 500 {object} responseErrorJSON
// @Success 502 {object} responseErrorJSON
// @Router /certificate/{issuer}/{domain} [delete]
func RevokeCertificateHandler(logger log.Logger, proxyClient *http.Client) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenValue, err := checkAuth(r)
		if err != nil {
			responseJSON(w, nil, err, http.StatusUnauthorized)
			return
		}

		w.Header().Set("Username", tokenValue.Username)

		certData := certstore.Certificate{
			Domain: r.PathValue("domain"),
			Issuer: r.PathValue("issuer"),
			Owner:  tokenValue.Username,
		}

		if certData.Domain == "" || certData.Issuer == "" {
			responseJSON(w, nil, fmt.Errorf("missing 'issuer' and/or 'domain' parameter"), http.StatusBadRequest)
			return
		}

		data, err := certstore.AmStore.GetKVRingCert(certstore.AmRingKey)
		if err != nil {
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}

		idx := slices.IndexFunc(data, func(c certstore.Certificate) bool {
			return c.Domain == certData.Domain && c.Issuer == certData.Issuer && c.Owner == certData.Owner
		})

		if idx == -1 {
			responseJSON(w, nil, fmt.Errorf("Certificate '%s' with issuer '%s' not found", certData.Domain, certData.Issuer), http.StatusNotFound)
			return
		}

		isLeaderNow, err := ring.IsLeader(certstore.AmStore.RingConfig)
		if err != nil {
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}
		if !isLeaderNow {
			host, _ := ring.GetLeaderIP(certstore.AmStore.RingConfig)
			_ = level.Info(logger).Log("msg", fmt.Sprintf("Forwarding '%s' request to '%s'", r.Method, host))
			body, _ := json.Marshal(certData)
			r.Body = io.NopCloser(bytes.NewReader(body))
			forwardRequest(proxyClient, host, w, r)
			return
		}

		// no concurrent task for the same certificate here
		certLockKey := certData.Issuer + "/" + certData.Domain

		_, locked := certLockMap.Load(certLockKey)
		if locked {
			responseJSON(w, nil, fmt.Errorf("Another operation is in progress"), http.StatusTooManyRequests)
			return
		}

		certLockMap.Store(certLockKey, r.Method)
		_ = level.Debug(logger).Log("msg", fmt.Sprintf("Locking operation for key '%s' on '%s' method", certLockKey, r.Method))
		defer func() { certLockMap.Delete(certLockKey) }() // Unlock deferred

		if !slices.Contains(tokenValue.Scope, "delete") {
			responseJSON(w, nil, fmt.Errorf("Invalid scope, missing 'delete' scope"), http.StatusForbidden)
			return
		}

		err = certstore.DeleteRemoteCertificateResource(certData, certstore.AmStore.Logger)
		if err != nil {
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}
		metrics.DecManagedCertificate(certData.Issuer, certData.Owner)

		data = slices.Delete(data, idx, idx+1)

		// udpate kv store
		certstore.AmStore.PutKVRing(certstore.AmRingKey, data)
		w.WriteHeader(http.StatusNoContent)
	})
}

func forwardRequest(proxyClient *http.Client, host string, w http.ResponseWriter, req *http.Request) {
	scheme := "http"
	if req.TLS != nil {
		scheme = "https"
	}
	port := strings.Split(req.Host, ":")[1]
	url := fmt.Sprintf("%s://%s:%s%s", scheme, host, port, req.RequestURI)

	proxyReq, err := http.NewRequest(req.Method, url, req.Body)
	if err != nil {
		responseJSON(w, nil, err, http.StatusInternalServerError)
		return
	}

	proxyReq.Header.Set("Host", req.Host)
	proxyReq.Header.Set("X-Forwarded-For", req.RemoteAddr)

	proxyReq.Header = make(http.Header)
	for h, val := range req.Header {
		proxyReq.Header[h] = val
	}

	resp, err := proxyClient.Do(proxyReq)
	if err != nil {
		responseJSON(w, nil, err, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		responseJSON(w, nil, err, http.StatusInternalServerError)
	}
}

func checkCSR(certParams CertificateParams) error {
	if certParams.CSR == "" {
		return fmt.Errorf("missing 'csr' parameter")
	}

	csrDecoded, err := base64.StdEncoding.DecodeString(certParams.CSR)
	if err != nil {
		return fmt.Errorf("Invalid 'csr' parameter, bad format: %v", err)
	}

	csr, err := certcrypto.PemDecodeTox509CSR([]byte(csrDecoded))
	if err != nil {
		return fmt.Errorf("Invalid 'csr' parameter: %v", err)
	}

	// checks domains, sstart with the common name
	domains := certcrypto.ExtractDomainsCSR(csr)

	var san []string
	if certParams.SAN != "" {
		san = strings.Split(certParams.SAN, ",")
	}

	if certParams.Domain != domains[0] {
		return fmt.Errorf("CSR Common Name should match 'domain' parameter. Domain '%s' - Common Name '%s'", certParams.Domain, domains[0])
	}

	if len(domains) > 1 && certParams.SAN == "" {
		return fmt.Errorf("CSR Domains should match 'SAN' parameter. SAN: %v - CSR domains: %v", san, domains[1:])
	}

	for _, domain := range san {
		if !slices.Contains(domains[1:], domain) {
			return fmt.Errorf("CSR Domains should match 'SAN' parameter. SAN: %v - CSR domains: %v", san, domains[1:])
		}
	}
	for _, domain := range domains[1:] {
		if !slices.Contains(san, domain) {
			return fmt.Errorf("CSR Domains should match 'SAN' parameter. SAN: %v - CSR domains: %v", san, domains[1:])
		}
	}
	return nil
}
