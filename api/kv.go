package api

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/fgouteroux/acme_manager/certstore"
	"github.com/fgouteroux/acme_manager/config"
	"github.com/fgouteroux/acme_manager/ring"
	"github.com/fgouteroux/acme_manager/utils"
)

type KVSyncResponse struct {
	Timestamp  time.Time `json:"timestamp"`
	TotalKeys  int       `json:"total_keys"`
	SyncedKeys []string  `json:"synced_keys"`
	FailedKeys []string  `json:"failed_keys"`
}

// manage kv

// KVSyncHandler godoc
// @Summary Sync kv data across all nodes
// @Description Sync kv keys data across all nodes from leader kv data
// @Tags kv
// @Produce  application/json
// @Param keys query string false "kv keys to sync"
// @Success 200 {object} KVSyncResponse
// @Success 400 {object} responseErrorJSON
// @Success 401 {object} responseErrorJSON
// @Success 403 {object} responseErrorJSON
// @Success 500 {object} responseErrorJSON
// @Router /kv/sync [post]
// @security APIKeyAuth
func KVSyncHandler(logger log.Logger) http.HandlerFunc {
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

		isLeader, err := ring.IsLeader(certstore.AmStore.RingConfig)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		// Only allow this operation on the leader
		if !isLeader {
			http.Error(w, "This operation can only be performed on the leader", http.StatusForbidden)
			return
		}

		leader, err := ring.GetLeader(certstore.AmStore.RingConfig)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		// optional parameter
		keysParam := r.URL.Query().Get("keys")

		var keys []string
		if keysParam != "" {
			keys = strings.Split(keysParam, ",")
		}

		availableKeys := certstore.AmStore.GetLocalCacheKeys()
		for _, k := range keys {
			if !slices.Contains(availableKeys, k) {
				responseJSON(w, nil, fmt.Errorf("invalid key '%s'. Available keys: %v", k, availableKeys), http.StatusBadRequest)
				return
			}
		}

		result, err := certstore.AmStore.KVSyncFromLeader(leader, keys)
		if err != nil {
			_ = level.Error(logger).Log("err", err)
			responseJSON(w, nil, fmt.Errorf("kv sync failed: %v", err), http.StatusInternalServerError)
			return
		}

		responseJSON(w, result, nil, http.StatusOK)
	})
}
