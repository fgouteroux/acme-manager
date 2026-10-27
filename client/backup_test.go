package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-kit/log"

	"github.com/fgouteroux/acme-manager/models"
	"github.com/fgouteroux/acme-manager/storage/vault"
	"github.com/fgouteroux/acme-manager/testhelper"
)

func selfSignedPair(t *testing.T, domain string) (string, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDer, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return string(cert), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer})
}

func TestBackupCertificateWithLocalKey(t *testing.T) {
	vaultTest := testhelper.GetTestVaultServer(t, false)
	defer vaultTest.Cleanup()

	previousClient, previousConfig, previousOwner := vault.GlobalClient, GlobalConfig, Owner
	defer func() { vault.GlobalClient, GlobalConfig, Owner = previousClient, previousConfig, previousOwner }()

	vault.GlobalClient = &vaultTest.Client
	GlobalConfig.Storage.Vault.CertPrefix = "certificates"
	Owner = "testfgx"

	const domain = "backup.example.com"
	keyFilePath := filepath.Join(t.TempDir(), domain+".key")
	cert := func(pem string) models.CertMap {
		return models.CertMap{
			Certificate: &models.Certificate{Issuer: "letsencrypt", Domain: domain},
			Cert:        pem,
			CAIssuer:    "ca chain",
		}
	}
	secretPath := certVaultPath(GlobalConfig.Storage.Vault.CertPrefix, Owner, "letsencrypt", "", domain)

	readBackup := func(t *testing.T) CertBackup {
		t.Helper()
		secret, err := vault.GlobalClient.GetSecretWithAppRole(secretPath)
		if err != nil {
			t.Fatal(err)
		}
		return MapInterfaceToCertBackup(secret)
	}

	originalCert, key := selfSignedPair(t, domain)
	if err := os.WriteFile(keyFilePath, key, 0600); err != nil {
		t.Fatal(err)
	}

	// Server-side renewal: new certificate, same key.
	backupCertificateWithLocalKey(log.NewNopLogger(), cert(originalCert), keyFilePath)
	got := readBackup(t)
	if got.Cert != originalCert || got.Key != string(key) || got.CAIssuer != "ca chain" {
		t.Fatalf("unexpected backup after renewal: %+v", got)
	}

	currentVersion := func(t *testing.T) int {
		t.Helper()
		meta, err := vault.GlobalClient.APIClient.KVv2(vault.GlobalClient.Config.SecretEngine).GetMetadata(context.Background(), secretPath)
		if err != nil {
			t.Fatal(err)
		}
		return meta.CurrentVersion
	}

	// Another client deploying the same renewal must not stack an identical version.
	version := currentVersion(t)
	backupCertificateWithLocalKey(log.NewNopLogger(), cert(originalCert), keyFilePath)
	if got := currentVersion(t); got != version {
		t.Fatalf("identical backup created version %d, want %d", got, version)
	}

	// A local key that does not match the certificate must not overwrite the backup.
	otherCert, _ := selfSignedPair(t, domain)
	backupCertificateWithLocalKey(log.NewNopLogger(), cert(otherCert), keyFilePath)
	if got := readBackup(t); got.Cert != originalCert || got.Key != string(key) {
		t.Fatalf("backup overwritten with a mismatched key pair: %+v", got)
	}

	// A missing local key must not overwrite the backup either.
	backupCertificateWithLocalKey(log.NewNopLogger(), cert(originalCert), keyFilePath+".missing")
	if got := readBackup(t); got.Key != string(key) {
		t.Fatalf("backup overwritten without a local key: %+v", got)
	}
}
