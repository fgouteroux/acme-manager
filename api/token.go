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
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/google/uuid"
	"github.com/prometheus/common/model"

	"github.com/fgouteroux/acme-manager/certstore"
	"github.com/fgouteroux/acme-manager/config"
	"github.com/fgouteroux/acme-manager/models"
	"github.com/fgouteroux/acme-manager/ring"
	"github.com/fgouteroux/acme-manager/storage/vault"
	"github.com/fgouteroux/acme-manager/utils"
)

var (
	allowedScope = []string{"create", "read", "update", "delete"}
)

// used to validate api body and by swagger
type TokenParams struct {
	ID       string   `json:"id" example:"021b5075-2d1e-44bd-b5e5-ffc7be7ad4c3"`
	Username string   `json:"username" example:"testfgx"`
	Scope    []string `json:"scope" example:"read,create,update,delete"`
	Duration string   `json:"duration" example:"30d"`
}

type TokenResponse struct {
	ID       string   `json:"id"`
	Token    string   `json:"token"`
	Hash     string   `json:"tokenHash"`
	Username string   `json:"username"`
	Expires  string   `json:"expires"`
	Duration string   `json:"duration"`
	Scope    []string `json:"scope"`
}

type TokenResponseGet struct {
	Hash     string   `json:"tokenHash"`
	Username string   `json:"username"`
	Expires  string   `json:"expires"`
	Duration string   `json:"duration"`
	Scope    []string `json:"scope"`
}

// manage token

// getToken godoc
//
//	@Summary		Read token
//	@Description	Return token infos like scope, expiration...
//	@Tags			token
//	@Produce		application/json
//	@Param			id	path		string	true	"Token ID"
//	@Success		200	{object}	TokenResponseGet
//	@Success		400	{object}	responseErrorJSON
//	@Success		401	{object}	responseErrorJSON
//	@Success		404	{object}	responseErrorJSON
//	@Success		500	{object}	responseErrorJSON
//	@Router			/token/{id} [get]
//	@security		APIKeyAuth
func GetTokenHandler(logger log.Logger) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if r.Header.Get("Authorization") != "" && r.PathValue("id") == "self" {
			tokenData, err := checkAuth(r)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				responseJSON(w, nil, err, http.StatusUnauthorized)
				return
			}
			responseJSON(w, tokenData, nil, http.StatusOK)
			return
		}

		authHeader := r.Header.Get("X-API-Key")
		if authHeader == "" {
			responseJSON(w, nil, fmt.Errorf("X-API-Key Header is missing or empty"), http.StatusUnauthorized)
			return
		}

		if utils.SHA1Hash(authHeader) != config.GlobalConfig.Common.APIKeyHash {
			responseJSON(w, nil, fmt.Errorf("API Key not valid"), http.StatusUnauthorized)
			return
		}

		ID := r.PathValue("id")
		if ID != "" {
			data, err := certstore.AmStore.GetToken(ID)
			if err != nil {
				if strings.Contains(err.Error(), "not found") {
					responseJSON(w, nil, err, http.StatusNotFound)
					return
				}
				_ = level.Error(logger).Log("err", err)
				responseJSON(w, nil, err, http.StatusInternalServerError)
				return
			}

			responseJSON(w, data, nil, http.StatusOK)
			return

		}
		http.Error(w, "Missing token ID", http.StatusBadRequest)
	})
}

// manage token

// createToken godoc
//
//	@Summary		Create token
//	@Description	Create token for a given username, scope and expiration time.
//	@Tags			token
//	@Produce		application/json
//	@Param			body	body		TokenParams	true	"Token Body"
//	@Success		201		{object}	TokenResponse
//	@Success		400		{object}	responseErrorJSON
//	@Success		401		{object}	responseErrorJSON
//	@Success		500		{object}	responseErrorJSON
//	@Router			/token [post]
//	@security		APIKeyAuth
func CreateTokenHandler(logger log.Logger, proxyClient *http.Client) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("X-API-Key")
		if authHeader == "" {
			responseJSON(w, nil, fmt.Errorf("X-API-Key Header is missing or empty"), http.StatusUnauthorized)
			return
		}

		if utils.SHA1Hash(authHeader) != config.GlobalConfig.Common.APIKeyHash {
			responseJSON(w, nil, fmt.Errorf("API Key not valid"), http.StatusUnauthorized)
			return
		}

		var token TokenParams
		err := json.NewDecoder(r.Body).Decode(&token)
		if err != nil {
			responseJSON(w, nil, err, http.StatusBadRequest)
			return
		}

		secretKeyPathPrefix := config.GlobalConfig.Storage.Vault.TokenPrefix
		if secretKeyPathPrefix == "" {
			secretKeyPathPrefix = "token"
		}

		if token.Username == "" || len(token.Scope) == 0 {
			responseJSON(w, nil, fmt.Errorf("missing/empty 'username' parameter"), http.StatusBadRequest)
			return
		}

		if len(token.Scope) == 0 {
			responseJSON(w, nil, fmt.Errorf("missing/empty 'scope' parameter"), http.StatusBadRequest)
			return
		}

		for _, scope := range token.Scope {
			if !slices.Contains(allowedScope, scope) {
				responseJSON(w, nil, fmt.Errorf("invalid scope value '%s', must be in %v", scope, allowedScope), http.StatusBadRequest)
				return
			}
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
			body, _ := json.Marshal(token)
			r.Body = io.NopCloser(bytes.NewReader(body))
			forwardRequest(logger, proxyClient, host, w, r)
			return
		}

		ID := uuid.New().String()
		randomToken, err := utils.RandomStringCrypto(32)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, nil, fmt.Errorf("error generating token: %v", err), http.StatusInternalServerError)
			return
		}

		var expires string
		if token.Duration == "" {
			expires = "Never"
		} else {
			duration, err := model.ParseDuration(token.Duration)
			if err != nil {
				responseJSON(w, nil, fmt.Errorf("invalid duration for 'expires' parameter: %v", err), http.StatusBadRequest)
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
			"duration":  token.Duration,
		}

		secretKeyPath := fmt.Sprintf("%s/%s/%s", secretKeyPathPrefix, token.Username, ID)
		err = vault.GlobalClient.PutSecretWithAppRole(secretKeyPath, newData)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}

		newToken := &models.Token{
			TokenHash: tokenHash,
			Scope:     token.Scope,
			Username:  token.Username,
			Expires:   expires,
			Duration:  token.Duration,
		}

		err = certstore.AmStore.PutToken(ID, newToken)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}
		responseJSON(w, newData, nil, http.StatusCreated)
	})
}

// manage token

// updateToken godoc
//
//	@Summary		Update token
//	@Description	Update token for a given username, scope and expiration time, it will generate a new token.
//	@Tags			token
//	@Produce		application/json
//	@Param			body	body		TokenParams	true	"Token Body"
//	@Success		200		{object}	TokenResponse
//	@Success		400		{object}	responseErrorJSON
//	@Success		401		{object}	responseErrorJSON
//	@Success		429		{object}	responseErrorJSON
//	@Success		500		{object}	responseErrorJSON
//	@Router			/token [put]
//	@security		APIKeyAuth
func UpdateTokenHandler(logger log.Logger, proxyClient *http.Client) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("X-API-Key")
		if authHeader == "" {
			responseJSON(w, nil, fmt.Errorf("X-API-Key Header is missing or empty"), http.StatusUnauthorized)
			return
		}

		if utils.SHA1Hash(authHeader) != config.GlobalConfig.Common.APIKeyHash {
			responseJSON(w, nil, fmt.Errorf("API Key not valid"), http.StatusUnauthorized)
			return
		}

		var token TokenParams
		err := json.NewDecoder(r.Body).Decode(&token)
		if err != nil {
			responseJSON(w, nil, err, http.StatusBadRequest)
			return
		}

		isLeaderNow, err := ring.IsLeader(certstore.AmStore.RingConfig)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}

		data, err := certstore.AmStore.GetToken(token.ID)
		if err != nil {
			if strings.Contains(err.Error(), "pending deletion") {
				responseJSON(w, nil, err, http.StatusConflict)
				return
			} else if strings.Contains(err.Error(), "not found") {
				responseJSON(w, nil, fmt.Errorf("token ID '%s' not found", token.ID), http.StatusNotFound)
				return
			}
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}

		secretKeyPathPrefix := config.GlobalConfig.Storage.Vault.TokenPrefix
		if secretKeyPathPrefix == "" {
			secretKeyPathPrefix = "token"
		}

		if token.Username == "" || len(token.Scope) == 0 {
			responseJSON(w, nil, fmt.Errorf("missing/empty 'username' parameter"), http.StatusBadRequest)
			return
		}

		if len(token.Scope) == 0 {
			responseJSON(w, nil, fmt.Errorf("missing/empty 'scope' parameter"), http.StatusBadRequest)
			return
		}

		for _, scope := range token.Scope {
			if !slices.Contains(allowedScope, scope) {
				responseJSON(w, nil, fmt.Errorf("invalid 'scope' must be in %v", allowedScope), http.StatusBadRequest)
				return
			}
		}

		if !isLeaderNow {
			host, _ := ring.GetLeaderIP(certstore.AmStore.RingConfig)
			_ = level.Info(logger).Log("msg", fmt.Sprintf("Forwarding '%s' request to '%s'", r.Method, host))
			body, _ := json.Marshal(token)
			r.Body = io.NopCloser(bytes.NewReader(body))
			forwardRequest(logger, proxyClient, host, w, r)
			return
		}

		randomToken, err := utils.RandomStringCrypto(32)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, nil, fmt.Errorf("error generating token: %v", err), http.StatusInternalServerError)
			return
		}

		var expires string
		if token.Duration == "" {
			expires = "Never"
		} else {
			duration, err := model.ParseDuration(token.Duration)
			if err != nil {
				responseJSON(w, nil, fmt.Errorf("invalid duration for 'expires' parameter: %v", err), http.StatusBadRequest)
				return
			}

			expiresRaw := time.Now().Add(time.Duration(duration))
			expires = expiresRaw.UTC().Format("2006-01-02 15:04:05 +0000 UTC")
		}

		tokenHash := utils.SHA1Hash(randomToken)

		newData := map[string]interface{}{
			"id":        token.ID,
			"token":     base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", token.ID, randomToken))),
			"tokenHash": tokenHash,
			"scope":     token.Scope,
			"username":  token.Username,
			"expires":   expires,
			"duration":  token.Duration,
		}

		secretKeyPath := fmt.Sprintf("%s/%s/%s", secretKeyPathPrefix, token.Username, token.ID)
		err = vault.GlobalClient.PutSecretWithAppRole(secretKeyPath, newData)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}

		data.TokenHash = tokenHash
		data.Scope = token.Scope
		data.Username = token.Username
		data.Expires = expires
		data.Duration = token.Duration

		err = certstore.AmStore.PutToken(token.ID, data)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}
		responseJSON(w, newData, nil, http.StatusOK)
	})
}

// manage token

// revokeToken godoc
//
//	@Summary		Revoke token
//	@Description	Revoke token for a given ID.
//	@Tags			token
//	@Produce		application/json
//	@Param			id	path	string	true	"Token ID"
//	@Success		204
//	@Success		401	{object}	responseErrorJSON
//	@Success		404	{object}	responseErrorJSON
//	@Success		500	{object}	responseErrorJSON
//	@Router			/token/{id} [delete]
//	@security		APIKeyAuth
func RevokeTokenHandler(logger log.Logger, proxyClient *http.Client) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("X-API-Key")
		if authHeader == "" {
			responseJSON(w, nil, fmt.Errorf("X-API-Key Header is missing or empty"), http.StatusUnauthorized)
			return
		}

		if utils.SHA1Hash(authHeader) != config.GlobalConfig.Common.APIKeyHash {
			responseJSON(w, nil, fmt.Errorf("API Key not valid"), http.StatusUnauthorized)
			return
		}

		isLeaderNow, err := ring.IsLeader(certstore.AmStore.RingConfig)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}

		ID := r.PathValue("id")
		if ID != "" {
			data, err := certstore.AmStore.GetToken(ID)
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

			if !isLeaderNow {
				host, _ := ring.GetLeaderIP(certstore.AmStore.RingConfig)
				_ = level.Info(logger).Log("msg", fmt.Sprintf("Forwarding '%s' request to '%s'", r.Method, host))
				forwardRequest(logger, proxyClient, host, w, r)
				return
			}

			secretKeyPathPrefix := config.GlobalConfig.Storage.Vault.TokenPrefix
			if secretKeyPathPrefix == "" {
				secretKeyPathPrefix = "token"
			}
			secretKeyPath := fmt.Sprintf("%s/%s/%s", secretKeyPathPrefix, data.Username, ID)
			err = vault.GlobalClient.DestroySecretWithAppRole(secretKeyPath)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				responseJSON(w, nil, err, http.StatusInternalServerError)
				return
			}

			err = certstore.AmStore.DeleteToken(ID)
			if err != nil {
				_ = level.Error(logger).Log("err", err)
				responseJSON(w, nil, err, http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}
		http.Error(w, "Missing token ID", http.StatusBadRequest)
	})
}
