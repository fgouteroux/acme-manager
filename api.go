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
	"time"

	"github.com/go-kit/log/level"
	"github.com/google/uuid"
	"github.com/prometheus/common/model"

	cert "github.com/fgouteroux/acme_manager/certificate"
	"github.com/fgouteroux/acme_manager/certstore"
	"github.com/fgouteroux/acme_manager/config"
	"github.com/fgouteroux/acme_manager/metrics"
	"github.com/fgouteroux/acme_manager/ring"
	"github.com/fgouteroux/acme_manager/storage/vault"
	"github.com/fgouteroux/acme_manager/utils"
)

var certLockMap sync.Map

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

func certificateMetadataHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		tokenValue, err := checkAuth(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		w.Header().Set("Username", tokenValue.Username)

		data, err := certstore.AmStore.GetKVRingCert(certstore.AmRingKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		issuer := r.URL.Query().Get("issuer")
		domain := r.URL.Query().Get("domain")

		if issuer != "" && domain != "" {
			idx := slices.IndexFunc(data, func(c cert.Certificate) bool {
				return c.Domain == domain && c.Issuer == issuer
			})
			if idx == -1 {
				http.Error(w, "Certificate not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			tmp, _ := json.Marshal(data[idx])
			_, _ = io.WriteString(w, string(tmp))
			return
		}

		var metadata []cert.Certificate
		for _, item := range data {

			if item.Owner == tokenValue.Username {
				metadata = append(metadata, item)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		tmp, _ := json.Marshal(metadata)
		_, _ = io.WriteString(w, string(tmp))
	})
}

func certificateHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenValue, err := checkAuth(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		w.Header().Set("Username", tokenValue.Username)

		var certData cert.Certificate
		err = json.NewDecoder(r.Body).Decode(&certData)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		certData.Owner = tokenValue.Username

		if certData.Domain == "" || certData.Issuer == "" {
			http.Error(w, "missing 'issuer' and/or 'domain' parameter", http.StatusBadRequest)
			return
		}

		data, err := certstore.AmStore.GetKVRingCert(certstore.AmRingKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		idx := slices.IndexFunc(data, func(c cert.Certificate) bool {
			return c.Domain == certData.Domain && c.Issuer == certData.Issuer
		})

		var owner string
		if idx != -1 {
			owner = data[idx].Owner
		}

		if r.Method == "GET" {
			if !slices.Contains(tokenValue.Scope, "read") {
				http.Error(w, "Invalid scope, missing 'read' scope", http.StatusForbidden)
				return
			}
			if idx == -1 || certData.Owner != owner {
				http.Error(w, "Certificate not found", http.StatusNotFound)
				return
			}
			secretKeyPath := fmt.Sprintf("%s/%s/%s", config.GlobalConfig.Storage.Vault.CertPrefix, certData.Issuer, certData.Domain)
			secret, err := vault.GlobalClient.GetSecretWithAppRole(secretKeyPath)
			if err != nil {
				http.Error(w, fmt.Sprintf("%v", err), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			secretBytes, _ := json.Marshal(secret)
			_, _ = io.WriteString(w, string(secretBytes))
			return
		}

		isLeaderNow, err := ring.IsLeader(certstore.AmStore.RingConfig)
		if err != nil {
			http.Error(w, fmt.Sprintf("%v", err), http.StatusInternalServerError)
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
			http.Error(w, "Another operation is in progress", http.StatusTooManyRequests)
			return
		}

		certLockMap.Store(certLockKey, r.Method)
		_ = level.Debug(logger).Log("msg", fmt.Sprintf("Locking operation for key '%s' on '%s' method", certLockKey, r.Method))
		defer func() { certLockMap.Delete(certLockKey) }() // Unlock deferred

		if r.Method == "POST" {
			if !slices.Contains(tokenValue.Scope, "create") {
				http.Error(w, "Invalid scope, missing 'create' scope", http.StatusForbidden)
				return
			}
			if idx == -1 {

				newCert, err := certstore.CreateRemoteCertificateResource(certData, certstore.AmStore.Logger)
				if err != nil {
					http.Error(w, fmt.Sprintf("%v", err), http.StatusInternalServerError)
					return
				}
				metrics.IncManagedCertificate(certData.Issuer)
				data = append(data, newCert)

				// udpate kv store
				certstore.AmStore.PutKVRing(certstore.AmRingKey, data)

				secretKeyPath := fmt.Sprintf("%s/%s/%s", config.GlobalConfig.Storage.Vault.CertPrefix, certData.Issuer, certData.Domain)
				secret, err := vault.GlobalClient.GetSecretWithAppRole(secretKeyPath)
				if err != nil {
					http.Error(w, fmt.Sprintf("%v", err), http.StatusInternalServerError)
					return
				}

				w.Header().Set("Content-Type", "application/json")
				secretBytes, _ := json.Marshal(secret)
				_, _ = io.WriteString(w, string(secretBytes))
				return

			}
			http.Error(w, "Certificate already exists", http.StatusBadRequest)
			return
		}

		if r.Method == "PUT" {
			if !slices.Contains(tokenValue.Scope, "update") {
				http.Error(w, "Invalid scope, missing 'update' scope", http.StatusForbidden)
				return
			}
			if idx != -1 && certData.Owner == owner {

				err := certstore.DeleteRemoteCertificateResource(certData.Domain, certData.Issuer, certstore.AmStore.Logger)
				if err != nil {
					http.Error(w, fmt.Sprintf("%v", err), http.StatusInternalServerError)
					return
				}
				metrics.DecManagedCertificate(certData.Issuer)

				data = slices.Delete(data, idx, idx+1)

				newCert, err := certstore.CreateRemoteCertificateResource(certData, certstore.AmStore.Logger)
				if err != nil {
					http.Error(w, fmt.Sprintf("%v", err), http.StatusInternalServerError)
					return
				}
				metrics.IncManagedCertificate(certData.Issuer)
				data = append(data, newCert)

				// udpate kv store
				certstore.AmStore.PutKVRing(certstore.AmRingKey, data)

				secretKeyPath := fmt.Sprintf("%s/%s/%s", config.GlobalConfig.Storage.Vault.CertPrefix, certData.Issuer, certData.Domain)
				secret, err := vault.GlobalClient.GetSecretWithAppRole(secretKeyPath)
				if err != nil {
					http.Error(w, fmt.Sprintf("%v", err), http.StatusInternalServerError)
					return
				}

				w.Header().Set("Content-Type", "application/json")
				secretBytes, _ := json.Marshal(secret)
				_, _ = io.WriteString(w, string(secretBytes))
				return
			}
			http.Error(w, "Certificate not found", http.StatusNotFound)
			return
		}

		if r.Method == "DELETE" {
			if !slices.Contains(tokenValue.Scope, "delete") {
				http.Error(w, "Invalid scope, missing 'delete' scope", http.StatusForbidden)
				return
			}
			if idx != -1 && certData.Owner == owner {

				err := certstore.DeleteRemoteCertificateResource(certData.Domain, certData.Issuer, certstore.AmStore.Logger)
				if err != nil {
					http.Error(w, fmt.Sprintf("%v", err), http.StatusInternalServerError)
					return
				}
				metrics.DecManagedCertificate(certData.Issuer)

				data = slices.Delete(data, idx, idx+1)

				// udpate kv store
				certstore.AmStore.PutKVRing(certstore.AmRingKey, data)
				_, _ = io.WriteString(w, "Deleted certificate")
				return
			}
			http.Error(w, "Certificate not found", http.StatusNotFound)
			return
		}
	})
}

func tokenHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("X-API-Key")
		if authHeader == "" {
			http.Error(w, "X-API-Key Header is missing or empty", http.StatusUnauthorized)
			return
		}

		if utils.SHA1Hash(authHeader) != config.GlobalConfig.Common.APIKeyHash {
			http.Error(w, "API Key not valid", http.StatusUnauthorized)
			return
		}

		allowedScope := []string{"create", "read", "update", "delete"}

		type Token struct {
			ID       string   `json:"id"`
			Username string   `json:"username"`
			Scope    []string `json:"scope"`
			Expires  string   `json:"expires"`
		}

		var token Token
		err := json.NewDecoder(r.Body).Decode(&token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		data, err := certstore.AmStore.GetKVRingToken(certstore.TokenRingKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		tokenData, tokenExists := data[token.ID]

		secretKeyPathPrefix := config.GlobalConfig.Storage.Vault.TokenPrefix
		if secretKeyPathPrefix == "" {
			secretKeyPathPrefix = "token"
		}

		if r.Method == "GET" {
			if !tokenExists {
				http.Error(w, "Token not found", http.StatusNotFound)
				return
			}
			output, _ := json.Marshal(tokenData)
			_, _ = io.WriteString(w, string(output))
		}

		if len(data) == 0 {
			data = make(map[string]certstore.Token, 1)
		}

		if r.Method == "POST" || r.Method == "PUT" {

			if token.Username == "" || len(token.Scope) == 0 {
				http.Error(w, "missing/empty 'username' parameter", http.StatusBadRequest)
				return
			}

			if len(token.Scope) == 0 {
				http.Error(w, "missing/empty 'scope' parameter", http.StatusBadRequest)
				return
			}

			for _, scope := range token.Scope {
				if !slices.Contains(allowedScope, scope) {
					http.Error(w, fmt.Sprintf("Invalid 'scope' must be in %v", allowedScope), http.StatusBadRequest)
					return
				}
			}

			if r.Method == "PUT" && !tokenExists {
				http.Error(w, "Token not found", http.StatusBadRequest)
				return
			} else if r.Method == "POST" && tokenExists {
				http.Error(w, "Token already exists", http.StatusBadRequest)
				return
			}

			var ID string
			if r.Method == "POST" {
				ID = uuid.New().String()
			} else {
				ID = token.ID
			}
			randomToken, err := utils.RandomStringCrypto(32)
			if err != nil {
				http.Error(w, fmt.Sprintf("Error generating token: %v", err), http.StatusInternalServerError)
				return
			}

			var expires string
			if token.Expires == "" {
				expires = "Never"
			} else {
				duration, err := model.ParseDuration(token.Expires)
				if err != nil {
					http.Error(w, fmt.Sprintf("Invalid duration for 'expires' parameter: %v", err), http.StatusBadRequest)
					return
				}

				expiresRaw := time.Now().Add(time.Duration(duration))
				expires = expiresRaw.UTC().Format("2006-01-02 15:04:05 +0000 UTC")
			}

			tokenHash := utils.SHA1Hash(randomToken)

			newData := map[string]interface{}{
				"id":        ID,
				"token":     base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", ID, randomToken))),
				"tokenHash": tokenHash,
				"scope":     token.Scope,
				"username":  token.Username,
				"expires":   expires,
			}

			secretKeyPath := fmt.Sprintf("%s/%s/%s", secretKeyPathPrefix, token.Username, ID)
			err = vault.GlobalClient.PutSecretWithAppRole(secretKeyPath, newData)
			if err != nil {
				http.Error(w, fmt.Sprintf("%v", err), http.StatusInternalServerError)
				return
			}

			data[ID] = certstore.Token{
				Hash:     tokenHash,
				Scope:    token.Scope,
				Username: token.Username,
				Expires:  expires,
			}

			// udpate kv store
			certstore.AmStore.PutKVRing(certstore.TokenRingKey, data)

			output, _ := json.Marshal(newData)
			_, _ = io.WriteString(w, string(output))
			return
		}

		if r.Method == "DELETE" {
			if tokenExists {
				secretKeyPath := fmt.Sprintf("%s/%s/%s", secretKeyPathPrefix, token.Username, token.ID)
				delete(data, token.ID)

				err = vault.GlobalClient.DeleteSecretWithAppRole(secretKeyPath)
				if err != nil {
					http.Error(w, fmt.Sprintf("%v", err), http.StatusInternalServerError)
					return
				}

				// udpate kv store
				certstore.AmStore.PutKVRing(certstore.TokenRingKey, data)
				_, _ = io.WriteString(w, "Revoked token")
				return
			}
			http.Error(w, "Token not found", http.StatusNotFound)
			return
		}
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	proxyReq.Header.Set("Host", req.Host)
	proxyReq.Header.Set("X-Forwarded-For", req.RemoteAddr)

	proxyReq.Header = make(http.Header)
	for h, val := range req.Header {
		proxyReq.Header[h] = val
	}

	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
