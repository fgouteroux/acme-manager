package utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"

	mathRand "math/rand"

	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/go-acme/lego/v4/certcrypto"

	"github.com/sirupsen/logrus"

	"golang.org/x/net/idna"
)

var labelNameRegexp = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// SanitizedDomain Make sure no funny chars are in the cert names (like wildcards ;)).
func SanitizedDomain(logger log.Logger, domain string) string {
	safe, err := idna.ToASCII(strings.NewReplacer(":", "-", "*", "_").Replace(domain))
	if err != nil {
		_ = level.Error(logger).Log("err", err)
	}
	return safe
}

func CreateNonExistingFolder(path string, mode fs.FileMode) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, mode)
	} else if err != nil {
		return err
	}
	return nil
}

func GenerateFingerprint(content []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(content))
}

func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func FormatFilePath(path string) string {
	arr := strings.Split(path, "/")
	return arr[len(arr)-1]
}

type UTCFormatter struct {
	logrus.Formatter
}

func (u UTCFormatter) Format(e *logrus.Entry) ([]byte, error) {
	e.Time = e.Time.UTC()
	return u.Formatter.Format(e)
}

func RandomStringCrypto(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

func StructToMapInterface(data interface{}) map[string]interface{} {
	val, _ := json.Marshal(data)
	var result map[string]interface{}
	_ = json.Unmarshal(val, &result)
	return result
}

// Get sha1 from string
func SHA1Hash(content string) string {
	hash := sha1.New()
	hash.Write([]byte(content))
	return hex.EncodeToString(hash.Sum(nil))
}

func SetTLSConfig(cert string, key string, ca string, insecure bool) (*tls.Config, error) {
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

// GenerateCSRAndPrivateKey generates a Certificate Signing Request (CSR) and a private key.
func GenerateCSRAndPrivateKey(privateKey, domain string, SAN []string) (string, []byte, error) {
	var pKey crypto.PrivateKey
	var err error
	if privateKey == "" {
		// Generate a new ECDSA key pair using the P-256 curve
		pKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", nil, err
		}
	} else {
		privateKeyBytes, err := os.ReadFile(filepath.Clean(privateKey))
		if err != nil {
			return "", nil, err
		}

		pKey, err = certcrypto.ParsePEMPrivateKey(privateKeyBytes)
		if err != nil {
			return "", nil, err
		}
	}

	opts := certcrypto.CSROptions{
		Domain: domain,
		SAN:    SAN,
	}

	// Create and sign the CSR using the private key
	csrBytes, err := certcrypto.CreateCSR(pKey, opts)
	if err != nil {
		return "", nil, err
	}

	// Encode the CSR in PEM format
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	// Encode the CSR PEM to bas64
	csr64 := base64.StdEncoding.EncodeToString(csrPEM)

	return csr64, certcrypto.PEMEncode(pKey), nil
}

func ValidateLabels(labels string) (errors []error) {
	for _, item := range strings.Split(labels, ",") {
		label := strings.Split(item, "=")

		if len(label) == 2 {
			if !labelNameRegexp.MatchString(label[0]) {
				errors = append(errors, fmt.Errorf(
					"Invalid Label Name '%s'. Must match the regex '%s'", label[0], labelNameRegexp))
			}

			if !utf8.ValidString(label[1]) {
				errors = append(errors, fmt.Errorf(
					"Invalid Label Value '%s': not a valid UTF8 string", label[1]))
			}
		}
	}
	return
}

// Function to generate a random weekday within a given range before an expiration date
func RandomWeekdayBeforeExpiration(expiration time.Time, minDays, maxDays int) time.Time {
	// Calculate the start and end dates for the range
	startDate := expiration.AddDate(0, 0, -maxDays)
	endDate := expiration.AddDate(0, 0, -minDays)

	// Calculate the number of weekdays in the range
	weekdays := 0
	for d := startDate; !d.After(endDate); d = d.AddDate(0, 0, 1) {
		if d.Weekday() != time.Saturday && d.Weekday() != time.Sunday {
			weekdays++
		}
	}

	// Select a random weekday within the range
	randomIndex := mathRand.Intn(weekdays)
	randomDate := startDate
	for i := 0; i <= randomIndex; randomDate = randomDate.AddDate(0, 0, 1) {
		if randomDate.Weekday() != time.Saturday && randomDate.Weekday() != time.Sunday {
			i++
		}
	}

	// Generate random hours and minutes
	randomHour := mathRand.Intn(24)
	randomMinute := mathRand.Intn(60)

	// Combine the random date and time
	return time.Date(randomDate.Year(), randomDate.Month(), randomDate.Day(), randomHour, randomMinute, 0, 0, randomDate.Location())
}

func ValidateRenewalDays(value string) (int, int, error) {
	var certRenewalMinDays, certRenewalMaxDays int
	var err error
	certRenewalDays := strings.Split(value, "-")
	if len(certRenewalDays) > 2 {
		return certRenewalMinDays, certRenewalMaxDays, fmt.Errorf("invalid value in 'cert_days_renewal': it should (min-days)-(max-days)' or 'days'")
	}

	if len(certRenewalDays) != 2 {
		certRenewalMinDays, err = strconv.Atoi(certRenewalDays[0])
		certRenewalMaxDays = certRenewalMinDays
		if err != nil {
			return certRenewalMinDays, certRenewalMaxDays, fmt.Errorf("invalid value in 'cert_days_renewal': %v", err)
		}
	} else {
		certRenewalMinDays, err = strconv.Atoi(certRenewalDays[0])
		if err != nil {
			return certRenewalMinDays, certRenewalMaxDays, fmt.Errorf("invalid value in 'cert_days_renewal': %v", err)
		}
		certRenewalMaxDays, err = strconv.Atoi(certRenewalDays[1])
		if err != nil {
			return certRenewalMinDays, certRenewalMaxDays, fmt.Errorf("invalid value in 'cert_days_renewal': %v", err)
		}
		if certRenewalMinDays > certRenewalMaxDays {
			return certRenewalMinDays, certRenewalMaxDays, fmt.Errorf("invalid value in 'cert_days_renewal': 'min-days' could not be higher than 'max-days'")
		}
		if certRenewalMaxDays < certRenewalMinDays {
			return certRenewalMinDays, certRenewalMaxDays, fmt.Errorf("invalid value in 'cert_days_renewal': 'max-days' could not be lower than 'min-days'")
		}
	}
	return certRenewalMinDays, certRenewalMaxDays, nil
}
