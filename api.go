package main

import (
	"fmt"
	"io"
	"net/http"
	//"strings"
	"encoding/json"
	"slices"

	cert "github.com/fgouteroux/acme_manager/certificate"
	"github.com/fgouteroux/acme_manager/certstore"
	"github.com/fgouteroux/acme_manager/config"
	"github.com/fgouteroux/acme_manager/metrics"
	"github.com/fgouteroux/acme_manager/storage/vault"
)

func certificateHandler(w http.ResponseWriter, r *http.Request) {

	var certData cert.Certificate
	err := json.NewDecoder(r.Body).Decode(&certData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

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

	if r.Method == "GET" {
		if idx == -1 {
			http.Error(w, "Certificate not found", http.StatusNotFound)
			return
		}
		secretKeyPath := fmt.Sprintf("%s/%s/%s", config.GlobalConfig.Storage.Vault.SecretPrefix, certData.Issuer, certData.Domain)
		secret, err := vault.GlobalClient.GetSecretWithAppRole(secretKeyPath)
		if err != nil {
			http.Error(w, fmt.Sprintf("%v", err), http.StatusInternalServerError)
			return
		}

		secretBytes, _ := json.Marshal(secret)

		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, string(secretBytes))
	}

	if r.Method == "POST" {
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

			_, _ = io.WriteString(w, "Created certificate")
			return

		}
		http.Error(w, "Certificate already exists", http.StatusBadRequest)
		return
	}

	if r.Method == "PUT" {
		if idx != -1 {

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

			_, _ = io.WriteString(w, "Updated certificate")
			return
		}
		http.Error(w, "Certificate not found", http.StatusNotFound)
		return
	}

	if r.Method == "DELETE" {
		if idx != -1 {

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
}
