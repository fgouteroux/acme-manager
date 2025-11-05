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

	"github.com/fgouteroux/acme-manager/certstore"
	"github.com/fgouteroux/acme-manager/config"
	"github.com/fgouteroux/acme-manager/metrics"
	"github.com/fgouteroux/acme-manager/models"
	"github.com/fgouteroux/acme-manager/ring"
	"github.com/fgouteroux/acme-manager/storage/vault"
	"github.com/fgouteroux/acme-manager/utils"
)

var certLockMap sync.Map

// responseErrorJSON example
type responseErrorJSON struct {
	Error string `json:"error" example:"error"`
}

func responseJSON(w http.ResponseWriter, data interface{}, err error, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {

		if data != nil {
			// If data is a map, add the error field; otherwise, create a new map
			var combinedData map[string]string
			if mData, ok := data.(map[string]string); ok {
				combinedData = mData
			} else {
				combinedData = make(map[string]string)
				// If data is not nil but not a map, this will ignore it for simplicity
				// You might want to handle this case differently depending on requirements
			}
			combinedData["err"] = err.Error()
			output, _ := json.Marshal(data)
			http.Error(w, string(output), statusCode)
		} else {
			output, _ := json.Marshal(&responseErrorJSON{Error: err.Error()})
			http.Error(w, string(output), statusCode)
		}
	} else {
		output, _ := json.Marshal(data)
		w.WriteHeader(statusCode)
		_, _ = w.Write(output)
	}
}

func checkAuth(r *http.Request) (*models.Token, error) {
	var tokenData *models.Token
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return tokenData, fmt.Errorf("authorization Header is missing or empty")
	}
	splitToken := strings.Split(authHeader, "Bearer ")
	if len(splitToken) != 2 {
		return tokenData, fmt.Errorf("invalid token format")
	}

	payload, err := base64.StdEncoding.DecodeString(splitToken[1])
	if err != nil {
		return tokenData, fmt.Errorf("invalid token format")
	}

	token := strings.SplitN(string(payload), ":", 2)
	if len(token) != 2 {
		return tokenData, fmt.Errorf("invalid token format")
	}

	tokenData, err = certstore.AmStore.GetToken(token[0])
	if err != nil {
		return tokenData, err
	}

	if tokenData.TokenHash != utils.SHA1Hash(token[1]) {
		return tokenData, fmt.Errorf("invalid token")
	}

	if tokenData.Expires != "Never" {
		layout := "2006-01-02 15:04:05 -0700 MST"
		t, err := time.Parse(layout, tokenData.Expires)
		if err != nil {
			return tokenData, fmt.Errorf("could not parse token expiration time")
		}

		if time.Now().After(t) {
			return tokenData, fmt.Errorf("token expired")
		}
	}

	return tokenData, nil
}

// manage metadata certificate

// certificateMetadata godoc
//
//	@Summary		Read metadata certificate
//	@Description	Return certificate metadata like SAN,expiration, fingerprint...
//	@Tags			metadata certificate
//	@Produce		application/json
//	@Param			Authorization	header		string	true	"Access token"			default(Bearer <Add access token here>)
//	@Param			issuer			query		string	false	"Certificate issuer"	default(letsencrypt)
//	@Param			domain			query		string	false	"Certificate domain"	default(testfgx.example.com)
//	@Success		200				{object}	[]models.Certificate
//	@Success		404				{object}	responseErrorJSON
//	@Success		409				{object}	responseErrorJSON
//	@Success		500				{object}	responseErrorJSON
//	@Router			/certificate/metadata [get]
func CertificateMetadataHandler(logger log.Logger, proxyClient *http.Client) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		tokenValue, err := checkAuth(r)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, nil, err, http.StatusUnauthorized)
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
			forwardRequest(logger, proxyClient, host, w, r)
			return
		}

		owner := tokenValue.Username
		w.Header().Set("user", owner)

		issuer := r.URL.Query().Get("issuer")
		domain := r.URL.Query().Get("domain")

		var metadata []*models.Certificate
		if issuer != "" && domain != "" {
			data, err := certstore.AmStore.GetCertificate(tokenValue.Username, issuer, domain)
			if err != nil {
				if strings.Contains(err.Error(), "pending deletion") {
					responseJSON(w, nil, err, http.StatusConflict)
					return
				} else if strings.Contains(err.Error(), "not found") {
					responseJSON(w, nil, err, http.StatusNotFound)
					return
				}
				_ = level.Error(logger).Log("err", err)
				responseJSON(w, nil, err, http.StatusInternalServerError)
				return
			}
			metadata = append(metadata, data)
		} else {
			metadata, err = certstore.AmStore.ListCertificatesForOwner(owner)
			if err != nil {
				responseJSON(w, metadata, err, http.StatusInternalServerError)
				return
			}

		}
		responseJSON(w, metadata, nil, http.StatusOK)
	})
}

// manage certificate

// certificate godoc
//
//	@Summary		Read certificate
//	@Description	Return certificate and issuer ca certificate.
//	@Tags			certificate
//	@Produce		application/json
//	@Param			Authorization	header		string	true	"Access token"			default(Bearer <Add access token here>)
//	@Param			issuer			path		string	true	"Certificate issuer"	default(letsencrypt)
//	@Param			domain			path		string	true	"Certificate domain"	default(testfgx.example.com)
//	@Success		200				{object}	models.CertMap
//	@Success		400				{object}	responseErrorJSON
//	@Success		401				{object}	responseErrorJSON
//	@Success		403				{object}	responseErrorJSON
//	@Success		404				{object}	responseErrorJSON
//	@Success		409				{object}	responseErrorJSON
//	@Success		500				{object}	responseErrorJSON
//	@Router			/certificate/{issuer}/{domain} [get]
func GetCertificateHandler(logger log.Logger, proxyClient *http.Client) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenValue, err := checkAuth(r)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, nil, err, http.StatusUnauthorized)
			return
		}

		w.Header().Set("user", tokenValue.Username)

		if !slices.Contains(tokenValue.Scope, "read") {
			responseJSON(w, nil, fmt.Errorf("invalid scope, missing 'read' scope"), http.StatusForbidden)
			return
		}

		certData := &models.Certificate{
			Domain: r.PathValue("domain"),
			Issuer: r.PathValue("issuer"),
			Owner:  tokenValue.Username,
		}

		if certData.Domain == "" || certData.Issuer == "" {
			responseJSON(w, nil, fmt.Errorf("missing 'issuer' and/or 'domain' parameter"), http.StatusBadRequest)
			return
		}

		jsonData := map[string]string{
			"user":   certData.Owner,
			"domain": certData.Domain,
			"issuer": certData.Issuer,
		}

		isLeaderNow, err := ring.IsLeader(certstore.AmStore.RingConfig)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, jsonData, err, http.StatusInternalServerError)
			return
		}

		if !isLeaderNow {
			host, _ := ring.GetLeaderIP(certstore.AmStore.RingConfig)
			_ = level.Info(logger).Log("msg", fmt.Sprintf("Forwarding '%s' request to '%s'", r.Method, host))
			forwardRequest(logger, proxyClient, host, w, r)
			return
		}

		_, err = certstore.AmStore.GetCertificate(certData.Owner, certData.Issuer, certData.Domain)
		if err != nil {
			if strings.Contains(err.Error(), "pending deletion") {
				responseJSON(w, nil, err, http.StatusConflict)
				return
			} else if strings.Contains(err.Error(), "not found") {
				responseJSON(w, jsonData, err, http.StatusNotFound)
				return
			}
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, jsonData, err, http.StatusInternalServerError)
			return
		}

		secretKeyPath := fmt.Sprintf("%s/%s/%s/%s", config.GlobalConfig.Storage.Vault.CertPrefix, certData.Owner, certData.Issuer, certData.Domain)
		secret, err := vault.GlobalClient.GetSecretWithAppRole(secretKeyPath)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, jsonData, err, http.StatusInternalServerError)
			return
		}

		responseJSON(w, certstore.MapInterfaceToCertMap(secret), nil, http.StatusOK)
	})
}

// manage certificate

// certificate godoc
//
//	@Summary		Create certificate
//	@Description	Create certificate for a given issuer and domain name.
//	@Tags			certificate
//	@Produce		application/json
//	@Param			Authorization	header		string				true	"Access token"	default(Bearer <Add access token here>)
//	@Param			body			body		models.CertificateParams	true	"Certificate body"
//	@Success		201				{object}	models.CertMap
//	@Success		400				{object}	responseErrorJSON
//	@Success		401				{object}	responseErrorJSON
//	@Success		403				{object}	responseErrorJSON
//	@Success		409				{object}	responseErrorJSON
//	@Success		429				{object}	responseErrorJSON
//	@Success		500				{object}	responseErrorJSON
//	@Success		502				{object}	responseErrorJSON
//	@Router			/certificate [post]
func CreateCertificateHandler(logger log.Logger, proxyClient *http.Client) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenValue, err := checkAuth(r)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, nil, err, http.StatusUnauthorized)
			return
		}

		w.Header().Set("user", tokenValue.Username)

		// validate the request body
		var certParams models.CertificateParams
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
			responseJSON(w, nil, fmt.Errorf("invalid issuer '%s' must be one of %v", certParams.Issuer, config.SupportedIssuers), http.StatusBadRequest)
			return
		}

		var renewalDays string
		if certParams.RenewalDays != "" {
			renewalDays = certParams.RenewalDays
		} else {
			renewalDays = config.GlobalConfig.Common.CertDaysRenewal
		}

		certRenewalMinDays, certRenewalMaxDays, err := utils.ValidateRenewalDays(renewalDays)
		if err != nil {
			responseJSON(w, nil, fmt.Errorf("%s", err), http.StatusBadRequest)
			return
		}

		if certParams.Days != 0 && (certRenewalMinDays >= certParams.Days || certRenewalMaxDays >= certParams.Days) {
			responseJSON(w, nil, fmt.Errorf("'renewal_days' (%s) should be lower than 'days' (%d)", certParams.RenewalDays, certParams.Days), http.StatusBadRequest)
			return
		}

		if certParams.DNSChallenge != "" && certParams.HTTPChallenge != "" {
			responseJSON(w, nil, fmt.Errorf("'dns_challenge' and 'http_challenge' are mutually exclusive"), http.StatusBadRequest)
			return
		}

		if certParams.Labels != "" {
			err := utils.ValidateLabels(certParams.Labels)
			if len(err) != 0 {
				responseJSON(w, nil, fmt.Errorf("%s", err), http.StatusBadRequest)
				return
			}
		}

		err = checkCSR(certParams)
		if err != nil {
			responseJSON(w, nil, err, http.StatusBadRequest)
			return
		}

		// convert request params to certificate object
		certBytes, _ := json.Marshal(certParams)
		var certData *models.Certificate
		err = json.Unmarshal(certBytes, &certData)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}

		certData.Owner = tokenValue.Username

		jsonData := map[string]string{
			"user":   certData.Owner,
			"domain": certData.Domain,
			"issuer": certData.Issuer,
		}

		isLeaderNow, err := ring.IsLeader(certstore.AmStore.RingConfig)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, jsonData, err, http.StatusInternalServerError)
			return
		}

		if !isLeaderNow {
			host, _ := ring.GetLeaderIP(certstore.AmStore.RingConfig)
			_ = level.Info(logger).Log("msg", fmt.Sprintf("Forwarding '%s' request to '%s'", r.Method, host))
			body, _ := json.Marshal(certData)
			r.Body = io.NopCloser(bytes.NewReader(body))
			forwardRequest(logger, proxyClient, host, w, r)
			return
		}

		_, err = certstore.AmStore.GetCertificate(certData.Owner, certData.Issuer, certData.Domain)
		if err == nil {
			responseJSON(w, jsonData, fmt.Errorf("certificate already exists"), http.StatusConflict)
			return
		} else if strings.Contains(err.Error(), "pending deletion") {
			responseJSON(w, nil, err, http.StatusConflict)
			return
		} else if !strings.Contains(err.Error(), "not found") {
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}

		// no concurrent task for the same certificate here
		certLockKey := certData.Owner + "/" + certData.Issuer + "/" + certData.Domain

		_, locked := certLockMap.Load(certLockKey)
		if locked {
			_ = level.Info(logger).Log("msg", "another create operation is in progress", "domain", certData.Domain, "issuer", certData.Issuer, "user", certData.Owner)

			responseJSON(w, jsonData, fmt.Errorf("another operation is in progress"), http.StatusTooManyRequests)
			return
		}

		certLockMap.Store(certLockKey, r.Method)
		_ = level.Debug(logger).Log("msg", fmt.Sprintf("Locking operation for key '%s' on '%s' method", certLockKey, r.Method))
		defer func() { certLockMap.Delete(certLockKey) }() // Unlock deferred

		if !slices.Contains(tokenValue.Scope, "create") {
			responseJSON(w, jsonData, fmt.Errorf("invalid scope, missing 'create' scope"), http.StatusForbidden)
			return
		}

		_ = level.Info(logger).Log("msg", "creating certificate", "domain", certData.Domain, "issuer", certData.Issuer, "user", certData.Owner)
		newCert, err := certstore.CreateRemoteCertificateResource(certData, certstore.AmStore.Logger)
		if err != nil {
			statusCode := http.StatusInternalServerError
			if strings.Contains(err.Error(), "urn:ietf:params:acme:error:malformed") {
				statusCode = http.StatusBadRequest
			}

			responseJSON(w, jsonData, err, statusCode)
			return
		}
		_ = level.Info(logger).Log("msg", "created certificate", "domain", certData.Domain, "issuer", certData.Issuer, "user", certData.Owner)
		metrics.IncManagedCertificate(certData.Issuer, certData.Owner)

		// Reset the renewed metric to ensure consistency (successful creation means no renewal issues)
		metrics.SetRenewedCertificate(certData.Issuer, certData.Owner, certData.Domain, 1)

		err = certstore.AmStore.PutCertificate(newCert)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, jsonData, err, http.StatusInternalServerError)
			return
		}

		secretKeyPath := fmt.Sprintf("%s/%s/%s/%s", config.GlobalConfig.Storage.Vault.CertPrefix, certData.Owner, certData.Issuer, certData.Domain)
		secret, err := vault.GlobalClient.GetSecretWithAppRole(secretKeyPath)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, jsonData, err, http.StatusInternalServerError)
			return
		}

		responseJSON(w, certstore.MapInterfaceToCertMap(secret), nil, http.StatusCreated)
	})
}

// manage certificate

// certificate godoc
//
//	@Summary		Update certificate
//	@Description	Update certificate will revoke the old and create a new certificate with given parameters.
//	@Tags			certificate
//	@Produce		application/json
//	@Param			Authorization	header		string				true	"Access token"	default(Bearer <Add access token here>)
//	@Param			body			body		models.CertificateParams	true	"Certificate body"
//	@Success		200				{object}	models.CertMap
//	@Success		400				{object}	responseErrorJSON
//	@Success		401				{object}	responseErrorJSON
//	@Success		403				{object}	responseErrorJSON
//	@Success		404				{object}	responseErrorJSON
//	@Success		409				{object}	responseErrorJSON
//	@Success		429				{object}	responseErrorJSON
//	@Success		500				{object}	responseErrorJSON
//	@Success		502				{object}	responseErrorJSON
//	@Router			/certificate [put]
func UpdateCertificateHandler(logger log.Logger, proxyClient *http.Client) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenValue, err := checkAuth(r)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, nil, err, http.StatusUnauthorized)
			return
		}

		w.Header().Set("user", tokenValue.Username)

		// validate the request body
		var certParams models.CertificateParams
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
			responseJSON(w, nil, fmt.Errorf("invalid issuer '%s' must be one of %v", certParams.Issuer, config.SupportedIssuers), http.StatusBadRequest)
			return
		}

		var certRenewalMinDays int
		var certRenewalMaxDays int
		var renewalDays string
		if certParams.RenewalDays != "" {
			renewalDays = certParams.RenewalDays
		} else {
			renewalDays = config.GlobalConfig.Common.CertDaysRenewal
		}

		certRenewalMinDays, certRenewalMaxDays, err = utils.ValidateRenewalDays(renewalDays)
		if err != nil {
			responseJSON(w, nil, fmt.Errorf("%s", err), http.StatusBadRequest)
			return
		}

		if certParams.Days != 0 {
			if certRenewalMinDays >= certParams.Days || certRenewalMaxDays >= certParams.Days {
				responseJSON(w, nil, fmt.Errorf("'renewal_days' (%s) should be lower than 'days' (%d)", certParams.RenewalDays, certParams.Days), http.StatusBadRequest)
				return
			}
		}

		if certParams.DNSChallenge != "" && certParams.HTTPChallenge != "" {
			responseJSON(w, nil, fmt.Errorf("'dns_challenge' and 'http_challenge' are mutually exclusive"), http.StatusBadRequest)
			return
		}

		if certParams.Labels != "" {
			err := utils.ValidateLabels(certParams.Labels)
			if len(err) != 0 {
				responseJSON(w, nil, fmt.Errorf("%s", err), http.StatusBadRequest)
				return
			}
		}

		err = checkCSR(certParams)
		if err != nil {
			responseJSON(w, nil, err, http.StatusBadRequest)
			return
		}

		// convert request params to certificate object
		certBytes, _ := json.Marshal(certParams)
		var certData *models.Certificate
		err = json.Unmarshal(certBytes, &certData)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}

		certData.Owner = tokenValue.Username

		jsonData := map[string]string{
			"user":   certData.Owner,
			"domain": certData.Domain,
			"issuer": certData.Issuer,
		}

		isLeaderNow, err := ring.IsLeader(certstore.AmStore.RingConfig)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, jsonData, err, http.StatusInternalServerError)
			return
		}

		if !isLeaderNow {
			host, _ := ring.GetLeaderIP(certstore.AmStore.RingConfig)
			_ = level.Info(logger).Log("msg", fmt.Sprintf("Forwarding '%s' request to '%s'", r.Method, host))
			body, _ := json.Marshal(certData)
			r.Body = io.NopCloser(bytes.NewReader(body))
			forwardRequest(logger, proxyClient, host, w, r)
			return
		}

		existingCert, err := certstore.AmStore.GetCertificate(certData.Owner, certData.Issuer, certData.Domain)
		if err != nil {
			if strings.Contains(err.Error(), "pending deletion") {
				responseJSON(w, nil, err, http.StatusConflict)
				return
			} else if strings.Contains(err.Error(), "not found") {
				responseJSON(w, nil, err, http.StatusNotFound)
				return
			}
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}

		// no concurrent task for the same certificate here
		certLockKey := certData.Owner + "/" + certData.Issuer + "/" + certData.Domain

		_, locked := certLockMap.Load(certLockKey)
		if locked {
			_ = level.Info(logger).Log("msg", "another update operation is in progress", "domain", certData.Domain, "issuer", certData.Issuer, "user", certData.Owner)
			responseJSON(w, jsonData, fmt.Errorf("another operation is in progress"), http.StatusTooManyRequests)
			return
		}

		certLockMap.Store(certLockKey, r.Method)
		_ = level.Debug(logger).Log("msg", fmt.Sprintf("Locking operation for key '%s' on '%s' method", certLockKey, r.Method))
		defer func() { certLockMap.Delete(certLockKey) }() // Unlock deferred

		if !slices.Contains(tokenValue.Scope, "update") {
			responseJSON(w, jsonData, fmt.Errorf("invalid scope, missing 'update' scope"), http.StatusForbidden)
			return
		}

		secretKeyPath := fmt.Sprintf("%s/%s/%s/%s", config.GlobalConfig.Storage.Vault.CertPrefix, certData.Owner, certData.Issuer, certData.Domain)

		var recreateCert bool
		if certData.San != existingCert.San {
			recreateCert = true
		}
		if certData.Days != existingCert.Days {
			recreateCert = true
		}
		if certData.Bundle != existingCert.Bundle {
			recreateCert = true
		}
		if certData.DnsChallenge != existingCert.DnsChallenge {
			recreateCert = true
		}
		if certData.HttpChallenge != existingCert.HttpChallenge {
			recreateCert = true
		}
		if certData.Csr != existingCert.Csr {
			recreateCert = true
		}
		if certData.KeyType != existingCert.KeyType {
			recreateCert = true
		}

		var newCert *models.Certificate
		var renewalDate string
		if recreateCert {
			if certParams.Revoke {
				_ = level.Info(logger).Log("msg", "revoking certificate", "domain", certData.Domain, "issuer", certData.Issuer, "user", certData.Owner)
				err = certstore.DeleteRemoteCertificateResource(certData, certstore.AmStore.Logger)
				if err != nil {
					_ = level.Error(logger).Log("err", err)
					responseJSON(w, jsonData, err, http.StatusInternalServerError)
					return
				}
				_ = level.Info(logger).Log("msg", "revoked certificate", "domain", certData.Domain, "issuer", certData.Issuer, "user", certData.Owner)
			}

			_ = level.Info(logger).Log("msg", "re-creating certificate", "domain", certData.Domain, "issuer", certData.Issuer, "user", certData.Owner)
			newCert, err = certstore.CreateRemoteCertificateResource(certData, certstore.AmStore.Logger)
			if err != nil {
				responseJSON(w, jsonData, err, http.StatusInternalServerError)
				return
			}
			_ = level.Info(logger).Log("msg", "re-created certificate", "domain", certData.Domain, "issuer", certData.Issuer, "user", certData.Owner)

			// Reset the renewed metric since we successfully recreated the certificate
			// This ensures that if a previous renewal failed (metric=0), it gets reset
			metrics.SetRenewedCertificate(certData.Issuer, certData.Owner, certData.Domain, 1)

			err = certstore.AmStore.PutCertificate(newCert)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				responseJSON(w, jsonData, err, http.StatusInternalServerError)
				return
			}
		} else {
			_ = level.Info(logger).Log("msg", "updating certificate", "domain", certData.Domain, "issuer", certData.Issuer, "user", certData.Owner)
			secret, err := vault.GlobalClient.GetSecretWithAppRole(secretKeyPath)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				responseJSON(w, jsonData, err, http.StatusInternalServerError)
				return
			}

			expiresDate, _ := time.Parse("2006-01-02 15:04:05 -0700 MST", secret["expires"].(string))
			renewalDate = utils.RandomWeekdayBeforeExpiration(expiresDate, certRenewalMinDays, certRenewalMaxDays).String()

			secret["renewal_date"] = renewalDate
			secret["renewal_days"] = certData.RenewalDays
			secret["labels"] = certData.Labels
			err = vault.GlobalClient.PutSecretWithAppRole(secretKeyPath, utils.StructToMapInterface(secret))
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				responseJSON(w, jsonData, err, http.StatusInternalServerError)
				return
			}
			// Update existing certificate metadata
			existingCert.RenewalDate = renewalDate
			existingCert.RenewalDays = certData.RenewalDays
			existingCert.Labels = certData.Labels

			err = certstore.AmStore.PutCertificate(existingCert)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				responseJSON(w, jsonData, err, http.StatusInternalServerError)
				return
			}
			_ = level.Info(logger).Log("msg", "updated certificate", "domain", certData.Domain, "issuer", certData.Issuer, "user", certData.Owner)
		}

		secret, err := vault.GlobalClient.GetSecretWithAppRole(secretKeyPath)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, jsonData, err, http.StatusInternalServerError)
			return
		}

		responseJSON(w, certstore.MapInterfaceToCertMap(secret), nil, http.StatusOK)
	})
}

// manage certificate

// certificate godoc
//
//	@Summary		Delete certificate
//	@Description	Delete certificate for the given issuer and domain name.
//	@Tags			certificate
//	@Produce		application/json
//	@Param			Authorization	header	string	true	"Access token"			default(Bearer <Add access token here>)
//	@Param			issuer			path	string	true	"Certificate issuer"	default(letsencrypt)
//	@Param			domain			path	string	true	"Certificate domain"	default(testfgx.example.com)
//	@Param			revoke			query	bool	false	"Revoke Certificate"	default(false)
//	@Success		204
//	@Success		400	{object}	responseErrorJSON
//	@Success		401	{object}	responseErrorJSON
//	@Success		403	{object}	responseErrorJSON
//	@Success		404	{object}	responseErrorJSON
//	@Success		409	{object}	responseErrorJSON
//	@Success		429	{object}	responseErrorJSON
//	@Success		500	{object}	responseErrorJSON
//	@Success		502	{object}	responseErrorJSON
//	@Router			/certificate/{issuer}/{domain} [delete]
func DeleteCertificateHandler(logger log.Logger, proxyClient *http.Client) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenValue, err := checkAuth(r)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, nil, err, http.StatusUnauthorized)
			return
		}

		var revoke bool
		revokeParam := r.URL.Query().Get("revoke")
		if revokeParam == "true" {
			revoke = true
		}

		w.Header().Set("user", tokenValue.Username)

		certData := &models.Certificate{
			Domain: r.PathValue("domain"),
			Issuer: r.PathValue("issuer"),
			Owner:  tokenValue.Username,
		}

		jsonData := map[string]string{
			"user":   certData.Owner,
			"domain": certData.Domain,
			"issuer": certData.Issuer,
		}

		if certData.Domain == "" || certData.Issuer == "" {
			responseJSON(w, jsonData, fmt.Errorf("missing 'issuer' and/or 'domain' parameter"), http.StatusBadRequest)
			return
		}

		isLeaderNow, err := ring.IsLeader(certstore.AmStore.RingConfig)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, jsonData, err, http.StatusInternalServerError)
			return
		}

		if !isLeaderNow {
			host, _ := ring.GetLeaderIP(certstore.AmStore.RingConfig)
			_ = level.Info(logger).Log("msg", fmt.Sprintf("Forwarding '%s' request to '%s'", r.Method, host))
			body, _ := json.Marshal(certData)
			r.Body = io.NopCloser(bytes.NewReader(body))
			forwardRequest(logger, proxyClient, host, w, r)
			return
		}

		_, err = certstore.AmStore.GetCertificate(certData.Owner, certData.Issuer, certData.Domain)
		if err != nil {
			if strings.Contains(err.Error(), "pending deletion") {
				responseJSON(w, nil, err, http.StatusConflict)
				return
			} else if strings.Contains(err.Error(), "not found") {
				responseJSON(w, nil, err, http.StatusNotFound)
				return
			}
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}

		// no concurrent task for the same certificate here
		certLockKey := certData.Owner + "/" + certData.Issuer + "/" + certData.Domain

		_, locked := certLockMap.Load(certLockKey)
		if locked {
			_ = level.Info(logger).Log("msg", "another delete operation is in progress", "domain", certData.Domain, "issuer", certData.Issuer, "user", certData.Owner)
			responseJSON(w, jsonData, fmt.Errorf("another operation is in progress"), http.StatusTooManyRequests)
			return
		}

		certLockMap.Store(certLockKey, r.Method)
		_ = level.Debug(logger).Log("msg", fmt.Sprintf("Locking operation for key '%s' on '%s' method", certLockKey, r.Method))
		defer func() { certLockMap.Delete(certLockKey) }() // Unlock deferred

		if !slices.Contains(tokenValue.Scope, "delete") {
			responseJSON(w, jsonData, fmt.Errorf("invalid scope, missing 'delete' scope"), http.StatusForbidden)
			return
		}

		if revoke {
			_ = level.Info(logger).Log("msg", "revoking certificate", "domain", certData.Domain, "issuer", certData.Issuer, "user", certData.Owner)
			err = certstore.DeleteRemoteCertificateResource(certData, certstore.AmStore.Logger)
			if err != nil {
				responseJSON(w, jsonData, err, http.StatusInternalServerError)
				return
			}
			_ = level.Info(logger).Log("msg", "revoked certificate", "domain", certData.Domain, "issuer", certData.Issuer, "user", certData.Owner)
		} else {
			_ = level.Info(logger).Log("msg", "deleting certificate", "domain", certData.Domain, "issuer", certData.Issuer, "user", certData.Owner)
			secretKeyPath := fmt.Sprintf("%s/%s/%s/%s", config.GlobalConfig.Storage.Vault.CertPrefix, certData.Owner, certData.Issuer, certData.Domain)
			err = vault.GlobalClient.DeleteSecretWithAppRole(secretKeyPath)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				responseJSON(w, jsonData, err, http.StatusInternalServerError)
				return
			}
			_ = level.Info(logger).Log("msg", "deleted certificate", "domain", certData.Domain, "issuer", certData.Issuer, "user", certData.Owner)
		}
		metrics.DecManagedCertificate(certData.Issuer, certData.Owner)

		err = certstore.AmStore.DeleteCertificate(certData.Owner, certData.Issuer, certData.Domain)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, jsonData, err, http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})
}

func forwardRequest(logger log.Logger, proxyClient *http.Client, host string, w http.ResponseWriter, req *http.Request) {
	scheme := "http"
	if req.TLS != nil {
		scheme = "https"
	}
	port := strings.Split(req.Host, ":")[1]
	url := fmt.Sprintf("%s://%s:%s%s", scheme, host, port, req.RequestURI)

	proxyReq, err := http.NewRequest(req.Method, url, req.Body)
	if err != nil {
		_ = level.Error(logger).Log("err", err)
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
		_ = level.Error(logger).Log("err", err)
		responseJSON(w, nil, err, http.StatusInternalServerError)
	}
}

func checkCSR(certParams models.CertificateParams) error {
	if certParams.Csr == "" {
		return fmt.Errorf("missing 'csr' parameter")
	}

	csrDecoded, err := base64.StdEncoding.DecodeString(certParams.Csr)
	if err != nil {
		return fmt.Errorf("invalid 'csr' parameter, bad format: %v", err)
	}

	csr, err := certcrypto.PemDecodeTox509CSR([]byte(csrDecoded))
	if err != nil {
		return fmt.Errorf("invalid 'csr' parameter: %v", err)
	}

	// checks domains, sstart with the common name
	domains := certcrypto.ExtractDomainsCSR(csr)

	var san []string
	if certParams.San != "" {
		san = strings.Split(certParams.San, ",")
	}

	if certParams.Domain != domains[0] {
		return fmt.Errorf("CSR Common Name should match 'domain' parameter. Domain '%s' - Common Name '%s'", certParams.Domain, domains[0])
	}

	if len(domains) > 1 && certParams.San == "" {
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
