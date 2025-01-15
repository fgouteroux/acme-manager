package main

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

	"github.com/go-kit/log/level"

	cert "github.com/fgouteroux/acme_manager/certificate"
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
	var tokenValue certstore.Token
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return tokenValue, fmt.Errorf("Authorization Header is missing or empty")
	}
	splitToken := strings.Split(authHeader, "Bearer ")
	if len(splitToken) != 2 {
		return tokenValue, fmt.Errorf("Invalid token format")
	}

	payload, err := base64.StdEncoding.DecodeString(splitToken[1])
	if err != nil {
		return tokenValue, fmt.Errorf("Invalid token format")
	}

	token := strings.SplitN(string(payload), ":", 2)
	if len(token) != 2 {
		return tokenValue, fmt.Errorf("Invalid token format")
	}

	tokenData, err := certstore.AmStore.GetKVRingToken(certstore.TokenRingKey)
	if err != nil {
		return tokenValue, err
	}

	var tokenExists bool
	tokenValue, tokenExists = tokenData[token[0]]
	if !tokenExists {
		return tokenValue, fmt.Errorf("Token not found")
	}

	reqTokenHash := utils.SHA1Hash(token[1])

	if tokenExists && reqTokenHash != tokenValue.Hash {
		return tokenValue, fmt.Errorf("Invalid token")
	}
	return tokenValue, nil
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
// @Success 200 {object} []cert.Certificate
// @Success 404 {object} responseErrorJSON
// @Success 500 {object} responseErrorJSON
// @Router /certificate/metadata [get]
func certificateMetadataHandler() http.HandlerFunc {
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

		var metadata []cert.Certificate
		if issuer != "" && domain != "" {
			idx := slices.IndexFunc(data, func(c cert.Certificate) bool {
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
// @Description Return certificate, private key and issuer ca certificate in base64 format.
// @Tags certificate
// @Produce  application/json
// @Param Authorization header string true "Access token" default(Bearer <Add access token here>)
// @Param issuer path string true "Certificate issuer" default(letsencrypt)
// @Param domain path string true "Certificate domain" default(testfgx.example.com)
// @Success 200 {object} cert.CertMap
// @Success 400 {object} responseErrorJSON
// @Success 401 {object} responseErrorJSON
// @Success 403 {object} responseErrorJSON
// @Success 404 {object} responseErrorJSON
// @Success 500 {object} responseErrorJSON
// @Router /certificate/{issuer}/{domain} [get]
func getCertificateHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenValue, err := checkAuth(r)
		if err != nil {
			responseJSON(w, nil, err, http.StatusUnauthorized)
			return
		}

		w.Header().Set("Username", tokenValue.Username)

		certData := &cert.Certificate{
			Domain: r.PathValue("domain"),
			Issuer: r.PathValue("issuer"),
			Owner:  tokenValue.Username,
		}

		if certData.Domain == "" || certData.Issuer == "" {
			responseJSON(w, "missing 'issuer' and/or 'domain' parameter", nil, http.StatusBadRequest)
			return
		}

		data, err := certstore.AmStore.GetKVRingCert(certstore.AmRingKey)
		if err != nil {
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}

		idx := slices.IndexFunc(data, func(c cert.Certificate) bool {
			return c.Domain == certData.Domain && c.Issuer == certData.Issuer
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
// @Success 201 {object} cert.CertMap
// @Success 400 {object} responseErrorJSON
// @Success 401 {object} responseErrorJSON
// @Success 403 {object} responseErrorJSON
// @Success 429 {object} responseErrorJSON
// @Success 500 {object} responseErrorJSON
// @Success 502 {object} responseErrorJSON
// @Router /certificate [post]
func createCertificateHandler() http.HandlerFunc {
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
			responseJSON(w, "missing 'issuer' and/or 'domain' parameter", nil, http.StatusBadRequest)
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

		// convert request params to certificate object
		certBytes, _ := json.Marshal(certParams)
		var certData cert.Certificate
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

		idx := slices.IndexFunc(data, func(c cert.Certificate) bool {
			return c.Domain == certData.Domain && c.Issuer == certData.Issuer
		})

		if idx >= 0 {
			responseJSON(w, nil, fmt.Errorf("Certificate already exists"), http.StatusBadRequest)
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
			forwardRequest(host, w, r)
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
			statusCode := http.StatusInternalServerError
			if strings.Contains(err.Error(), "urn:ietf:params:acme:error:malformed") {
				statusCode = http.StatusBadRequest
			}

			responseJSON(w, nil, err, statusCode)
			return
		}
		metrics.IncManagedCertificate(certData.Issuer)
		data = append(data, newCert)

		// udpate kv store
		certstore.AmStore.PutKVRing(certstore.AmRingKey, data)

		secretKeyPath := fmt.Sprintf("%s/%s/%s", config.GlobalConfig.Storage.Vault.CertPrefix, certData.Issuer, certData.Domain)
		secret, err := vault.GlobalClient.GetSecretWithAppRole(secretKeyPath)
		if err != nil {
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
// @Success 200 {object} cert.CertMap
// @Success 400 {object} responseErrorJSON
// @Success 401 {object} responseErrorJSON
// @Success 403 {object} responseErrorJSON
// @Success 404 {object} responseErrorJSON
// @Success 429 {object} responseErrorJSON
// @Success 500 {object} responseErrorJSON
// @Success 502 {object} responseErrorJSON
// @Router /certificate [put]
func updateCertificateHandler() http.HandlerFunc {
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
			responseJSON(w, "missing 'issuer' and/or 'domain' parameter", nil, http.StatusBadRequest)
			return
		}

		if !slices.Contains(config.SupportedIssuers, certParams.Issuer) {
			responseJSON(w, nil, fmt.Errorf("Invalid issuer '%s' must be one of %v", certParams.Issuer, config.SupportedIssuers), http.StatusBadRequest)
			return
		}

		if certParams.RenewalDays >= certParams.Days {
			responseJSON(w, nil, fmt.Errorf("'renewal_days' (%d) should be lower than 'days' (%d)", certParams.RenewalDays, certParams.Days), http.StatusBadRequest)
			return
		}

		if certParams.DNSChallenge != "" && certParams.HTTPChallenge != "" {
			responseJSON(w, nil, fmt.Errorf("'dns_challenge' and 'http_challenge' are mutually exclusive"), http.StatusBadRequest)
			return
		}

		// convert request params to certificate object
		certBytes, _ := json.Marshal(certParams)
		var certData cert.Certificate
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

		idx := slices.IndexFunc(data, func(c cert.Certificate) bool {
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
			forwardRequest(host, w, r)
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

		err = certstore.DeleteRemoteCertificateResource(certData.Domain, certData.Issuer, certstore.AmStore.Logger)
		if err != nil {
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}
		metrics.DecManagedCertificate(certData.Issuer)

		data = slices.Delete(data, idx, idx+1)

		newCert, err := certstore.CreateRemoteCertificateResource(certData, certstore.AmStore.Logger)
		if err != nil {
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}
		metrics.IncManagedCertificate(certData.Issuer)
		data = append(data, newCert)

		// udpate kv store
		certstore.AmStore.PutKVRing(certstore.AmRingKey, data)

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
func revokeCertificateHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenValue, err := checkAuth(r)
		if err != nil {
			responseJSON(w, nil, err, http.StatusUnauthorized)
			return
		}

		w.Header().Set("Username", tokenValue.Username)

		certData := &cert.Certificate{
			Domain: r.PathValue("domain"),
			Issuer: r.PathValue("issuer"),
			Owner:  tokenValue.Username,
		}

		if certData.Domain == "" || certData.Issuer == "" {
			responseJSON(w, "missing 'issuer' and/or 'domain' parameter", nil, http.StatusBadRequest)
			return
		}

		data, err := certstore.AmStore.GetKVRingCert(certstore.AmRingKey)
		if err != nil {
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}

		idx := slices.IndexFunc(data, func(c cert.Certificate) bool {
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
			forwardRequest(host, w, r)
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

		err = certstore.DeleteRemoteCertificateResource(certData.Domain, certData.Issuer, certstore.AmStore.Logger)
		if err != nil {
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}
		metrics.DecManagedCertificate(certData.Issuer)

		data = slices.Delete(data, idx, idx+1)

		// udpate kv store
		certstore.AmStore.PutKVRing(certstore.AmRingKey, data)
		w.WriteHeader(http.StatusNoContent)
	})
}

func forwardRequest(host string, w http.ResponseWriter, req *http.Request) {
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
