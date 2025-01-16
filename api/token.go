package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/common/model"

	"github.com/fgouteroux/acme_manager/certstore"
	"github.com/fgouteroux/acme_manager/config"
	"github.com/fgouteroux/acme_manager/storage/vault"
	"github.com/fgouteroux/acme_manager/utils"
)

var (
	allowedScope = []string{"create", "read", "update", "delete"}
)

// used to validate api body and by swagger
type TokenParams struct {
	ID       string   `json:"id" example:"021b5075-2d1e-44bd-b5e5-ffc7be7ad4c3"`
	Username string   `json:"username" example:"testfgx"`
	Scope    []string `json:"scope" example:"read,create,update,delete"`
	Expires  string   `json:"expires" example:"30d"`
}

// manage token

// getToken godoc
// @Summary Read token
// @Description Return token infos like scope, expiration...
// @Tags token
// @Produce  application/json
// @Param id path string true "Token ID"
// @Success 200 {object} certstore.Token
// @Success 400 {object} responseErrorJSON
// @Success 401 {object} responseErrorJSON
// @Success 404 {object} responseErrorJSON
// @Success 500 {object} responseErrorJSON
// @Router /token/{id} [get]
// @security APIKeyAuth
func GetTokenHandler() http.HandlerFunc {
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

		ID := r.PathValue("id")
		if ID != "" {
			data, err := certstore.AmStore.GetKVRingToken(certstore.TokenRingKey)
			if err != nil {
				responseJSON(w, nil, err, http.StatusInternalServerError)
				return
			}

			tokenData, tokenExists := data[ID]
			if tokenExists {
				responseJSON(w, tokenData, nil, http.StatusOK)
				return
			}
			responseJSON(w, nil, fmt.Errorf("Token ID '%s' not found", ID), http.StatusNotFound)
			return
		}
		http.Error(w, "Missing token ID", http.StatusBadRequest)
	})
}

// manage token

// createToken godoc
// @Summary Create token
// @Description Create token for a given username, scope and expiration time.
// @Tags token
// @Produce  application/json
// @Param body body TokenParams true "Token Body"
// @Success 201 {object} map[string]interface{}
// @Success 400 {object} responseErrorJSON
// @Success 401 {object} responseErrorJSON
// @Success 500 {object} responseErrorJSON
// @Router /token [post]
// @security APIKeyAuth
func CreateTokenHandler() http.HandlerFunc {
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

		data, err := certstore.AmStore.GetKVRingToken(certstore.TokenRingKey)
		if err != nil {
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}

		secretKeyPathPrefix := config.GlobalConfig.Storage.Vault.TokenPrefix
		if secretKeyPathPrefix == "" {
			secretKeyPathPrefix = "token"
		}

		if len(data) == 0 {
			data = make(map[string]certstore.Token, 1)
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
				responseJSON(w, nil, fmt.Errorf("Invalid scope value '%s', must be in %v", scope, allowedScope), http.StatusBadRequest)
				return
			}
		}

		ID := uuid.New().String()
		randomToken, err := utils.RandomStringCrypto(32)
		if err != nil {
			responseJSON(w, nil, fmt.Errorf("Error generating token: %v", err), http.StatusInternalServerError)
			return
		}

		var expires string
		if token.Expires == "" {
			expires = "Never"
		} else {
			duration, err := model.ParseDuration(token.Expires)
			if err != nil {
				responseJSON(w, nil, fmt.Errorf("Invalid duration for 'expires' parameter: %v", err), http.StatusBadRequest)
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
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}

		data[ID] = certstore.Token{
			TokenHash: tokenHash,
			Scope:     token.Scope,
			Username:  token.Username,
			Expires:   expires,
		}

		// udpate kv store
		certstore.AmStore.PutKVRing(certstore.TokenRingKey, data)

		responseJSON(w, newData, nil, http.StatusCreated)
	})
}

// manage token

// updateToken godoc
// @Summary Update token
// @Description Update token for a given username, scope and expiration time, it will generate a new token.
// @Tags token
// @Produce  application/json
// @Param body body TokenParams true "Token Body"
// @Success 200 {object} map[string]interface{}
// @Success 400 {object} responseErrorJSON
// @Success 401 {object} responseErrorJSON
// @Success 429 {object} responseErrorJSON
// @Success 500 {object} responseErrorJSON
// @Router /token [put]
// @security APIKeyAuth
func UpdateTokenHandler() http.HandlerFunc {
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

		data, err := certstore.AmStore.GetKVRingToken(certstore.TokenRingKey)
		if err != nil {
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}

		_, tokenExists := data[token.ID]
		if !tokenExists {
			responseJSON(w, nil, fmt.Errorf("Token ID '%s' not found", token.ID), http.StatusNotFound)
			return
		}

		secretKeyPathPrefix := config.GlobalConfig.Storage.Vault.TokenPrefix
		if secretKeyPathPrefix == "" {
			secretKeyPathPrefix = "token"
		}

		if len(data) == 0 {
			data = make(map[string]certstore.Token, 1)
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
				responseJSON(w, nil, fmt.Errorf("Invalid 'scope' must be in %v", allowedScope), http.StatusBadRequest)
				return
			}
		}

		randomToken, err := utils.RandomStringCrypto(32)
		if err != nil {
			responseJSON(w, nil, fmt.Errorf("Error generating token: %v", err), http.StatusInternalServerError)
			return
		}

		var expires string
		if token.Expires == "" {
			expires = "Never"
		} else {
			duration, err := model.ParseDuration(token.Expires)
			if err != nil {
				responseJSON(w, nil, fmt.Errorf("Invalid duration for 'expires' parameter: %v", err), http.StatusBadRequest)
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
		}

		secretKeyPath := fmt.Sprintf("%s/%s/%s", secretKeyPathPrefix, token.Username, token.ID)
		err = vault.GlobalClient.PutSecretWithAppRole(secretKeyPath, newData)
		if err != nil {
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}

		data[token.ID] = certstore.Token{
			TokenHash: tokenHash,
			Scope:     token.Scope,
			Username:  token.Username,
			Expires:   expires,
		}

		// udpate kv store
		certstore.AmStore.PutKVRing(certstore.TokenRingKey, data)

		responseJSON(w, newData, nil, http.StatusOK)
	})
}

// manage token

// revokeToken godoc
// @Summary Revoke token
// @Description Revoke token for a given ID.
// @Tags token
// @Produce  application/json
// @Param id path string true "Token ID"
// @Success 204
// @Success 401 {object} responseErrorJSON
// @Success 404 {object} responseErrorJSON
// @Success 500 {object} responseErrorJSON
// @Router /token/{id} [delete]
// @security APIKeyAuth
func RevokeTokenHandler() http.HandlerFunc {
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

		data, err := certstore.AmStore.GetKVRingToken(certstore.TokenRingKey)
		if err != nil {
			responseJSON(w, nil, err, http.StatusInternalServerError)
			return
		}

		ID := r.PathValue("id")
		if ID != "" {
			tokenData, tokenExists := data[ID]
			if tokenExists {
				secretKeyPathPrefix := config.GlobalConfig.Storage.Vault.TokenPrefix
				if secretKeyPathPrefix == "" {
					secretKeyPathPrefix = "token"
				}
				secretKeyPath := fmt.Sprintf("%s/%s/%s", secretKeyPathPrefix, tokenData.Username, ID)
				delete(data, ID)

				err = vault.GlobalClient.DeleteSecretWithAppRole(secretKeyPath)
				if err != nil {
					responseJSON(w, nil, err, http.StatusInternalServerError)
					return
				}

				// udpate kv store
				certstore.AmStore.PutKVRing(certstore.TokenRingKey, data)

				w.WriteHeader(http.StatusNoContent)
				return
			}
			responseJSON(w, nil, fmt.Errorf("Token ID '%s' not found", ID), http.StatusNotFound)
		}
		http.Error(w, "Missing token ID", http.StatusBadRequest)
	})
}
