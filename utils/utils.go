//nolint:revive // utils package contains various utility functions
package utils

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"

	mathRand "math/rand"

	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/go-acme/lego/v5/certcrypto"
	legoLog "github.com/go-acme/lego/v5/log"
	"github.com/hashicorp/go-retryablehttp"

	"github.com/sirupsen/logrus"

	"golang.org/x/net/idna"
)

var labelNameRegexp = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// contextKey is a private type for context keys to avoid collisions
type contextKey string

const requestIDKey contextKey = "request_id"

// GenerateRequestID generates a unique request ID using crypto/rand
func GenerateRequestID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback to timestamp-based ID if random fails
		return fmt.Sprintf("req_%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("req_%s", hex.EncodeToString(b))
}

// WithRequestID adds a request ID to the context
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

// GetRequestID retrieves the request ID from the context
func GetRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value(requestIDKey).(string); ok {
		return requestID
	}
	return ""
}

// LoggerWithRequestID returns a logger with the request ID from context
func LoggerWithRequestID(ctx context.Context, logger log.Logger) log.Logger {
	requestID := GetRequestID(ctx)
	if requestID != "" {
		return log.With(logger, "request_id", requestID)
	}
	return logger
}

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
func GenerateCSRAndPrivateKey(privateKey, keyType, domain string, SAN []string) (string, []byte, error) {
	var pKey crypto.PrivateKey
	var err error
	if privateKey == "" {
		certKeyType, err := GetKeyType(keyType)
		if err != nil {
			return "", nil, err
		}
		pKey, err = certcrypto.GeneratePrivateKey(certKeyType)
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

// GetKeyType the type from which private keys should be generated.
func GetKeyType(keyTypeStr string) (certcrypto.KeyType, error) {
	switch strings.ToUpper(keyTypeStr) {
	case "RSA2048":
		return certcrypto.RSA2048, nil
	case "RSA3072":
		return certcrypto.RSA3072, nil
	case "RSA4096":
		return certcrypto.RSA4096, nil
	case "RSA8192":
		return certcrypto.RSA8192, nil
	case "EC256":
		return certcrypto.EC256, nil
	case "EC384":
		return certcrypto.EC384, nil
	default:
		var zeroKeyType certcrypto.KeyType
		return zeroKeyType, fmt.Errorf("unsupported key type: %s", keyTypeStr)
	}
}

func ValidateLabels(labels string) (errors []error) {
	for _, item := range strings.Split(labels, ",") {
		label := strings.Split(item, "=")

		if len(label) == 2 {
			if !labelNameRegexp.MatchString(label[0]) {
				errors = append(errors, fmt.Errorf(
					"invalid Label Name '%s'. Must match the regex '%s'", label[0], labelNameRegexp))
			}

			if !utf8.ValidString(label[1]) {
				errors = append(errors, fmt.Errorf(
					"invalid Label Value '%s': not a valid UTF8 string", label[1]))
			}
		}
	}
	return
}

// Function to generate a random weekday within a given range before an expiration date
func RandomWeekdayBeforeExpiration(expiration time.Time, minDays, maxDays int) time.Time {
	now := time.Now()

	// Calculate the start and end dates for the range
	startDate := expiration.AddDate(0, 0, -maxDays)
	endDate := expiration.AddDate(0, 0, -minDays)

	// For short-lived certificates where renewal window is in the past,
	// adjust to use a percentage-based approach (renew at ~50-75% of lifetime)
	if endDate.Before(now) {
		// Calculate certificate lifetime in hours
		lifetime := expiration.Sub(now)
		if lifetime <= 0 {
			// Certificate already expired, return now
			return now
		}

		// Renew between 50% and 75% of remaining lifetime
		minLifetimePercent := 0.50
		maxLifetimePercent := 0.75

		minDuration := time.Duration(float64(lifetime) * minLifetimePercent)
		maxDuration := time.Duration(float64(lifetime) * maxLifetimePercent)

		// Random duration between min and max
		durationRange := maxDuration - minDuration
		if durationRange <= 0 {
			durationRange = time.Hour
		}
		randomDuration := minDuration + time.Duration(mathRand.Int63n(int64(durationRange)))

		renewalDate := now.Add(randomDuration)

		// Generate random hours and minutes
		randomHour := mathRand.Intn(24)
		randomMinute := mathRand.Intn(60)

		return time.Date(renewalDate.Year(), renewalDate.Month(), renewalDate.Day(), randomHour, randomMinute, 0, 0, renewalDate.Location())
	}

	// Ensure startDate is not in the past
	if startDate.Before(now) {
		startDate = now
	}

	// Calculate the number of weekdays in the range
	weekdays := 0
	for d := startDate; !d.After(endDate); d = d.AddDate(0, 0, 1) {
		if d.Weekday() != time.Saturday && d.Weekday() != time.Sunday {
			weekdays++
		}
	}

	// If no weekdays in range, use startDate
	if weekdays == 0 {
		randomHour := mathRand.Intn(24)
		randomMinute := mathRand.Intn(60)
		return time.Date(startDate.Year(), startDate.Month(), startDate.Day(), randomHour, randomMinute, 0, 0, startDate.Location())
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

// ResponseLogHook logs the response status code and body
func ResponseLogHook(logger *logrus.Logger, logJSONBody bool) retryablehttp.ResponseLogHook {
	return func(_ retryablehttp.Logger, resp *http.Response) {
		// Log order URL at INFO level when a new order is created (status 201 and new-order endpoint)
		if resp.StatusCode == 201 && strings.Contains(resp.Request.URL.Path, "/new-order") {
			if location := resp.Header.Get("Location"); location != "" {
				logger.WithFields(logrus.Fields{
					"url": resp.Request.URL.String(),
				}).Infof("ACME order created OrderURL: %s", location)
			}
		}

		if resp.StatusCode >= 400 {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				fields := logrus.Fields{"err": fmt.Sprintf("url: %s\nbody_error: %v", resp.Request.URL.String(), err)}
				logger.WithFields(fields).Errorf("Failed to read response body")
				return
			}

			errMsg := fmt.Sprintf("url: %s\nbody: %s", resp.Request.URL.String(), string(body))
			fields := logrus.Fields{"err": errMsg}

			if logJSONBody {
				// Try to unmarshal the body as JSON
				var jsonData map[string]interface{}
				err = json.Unmarshal(body, &jsonData)
				if err != nil {
					// If not JSON, keep the original err message
					fields["err"] = fmt.Sprintf("%s\njson_parse_error: %v", errMsg, err)
				} else {
					// If JSON, log each field in addition to the err field
					for key, value := range jsonData {
						if key == "err" {
							// Rename conflicting err field from JSON to avoid overwriting our err field
							fields["response_err"] = value
						} else {
							fields[key] = value
						}
					}
				}
			}

			errMsg = fmt.Sprintf("Request failed with status code %d", resp.StatusCode)
			if resp.StatusCode == 429 {
				errMsg = errMsg + ". Retrying..."
			}
			logger.WithFields(fields).Error(errMsg)
			// Restore the body content to the response
			resp.Body = io.NopCloser(bytes.NewBuffer(body))
		}
	}
}

// ResponseLogHookDebug logs all responses with full details
func ResponseLogHookDebug(logger *logrus.Logger) retryablehttp.ResponseLogHook {
	return func(_ retryablehttp.Logger, resp *http.Response) {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fields := logrus.Fields{
				"method":      resp.Request.Method,
				"url":         resp.Request.URL.String(),
				"status_code": resp.StatusCode,
				"err":         fmt.Sprintf("body_error: %v", err),
			}
			logger.WithFields(fields).Debugf("HTTP Response (failed to read body)")
			return
		}

		fields := logrus.Fields{
			"method":      resp.Request.Method,
			"url":         resp.Request.URL.String(),
			"status_code": resp.StatusCode,
			"body":        string(body),
		}

		// Log response headers
		for key, values := range resp.Header {
			fields[fmt.Sprintf("header_%s", key)] = strings.Join(values, ",")
		}

		logger.WithFields(fields).Debugf("HTTP Response")

		// Restore the body content to the response
		resp.Body = io.NopCloser(bytes.NewBuffer(body))
	}
}

// RequestLogHook logs outgoing HTTP requests
func RequestLogHook(logger *logrus.Logger) retryablehttp.RequestLogHook {
	return func(_ retryablehttp.Logger, req *http.Request, attempt int) {
		fields := logrus.Fields{
			"method":  req.Method,
			"url":     req.URL.String(),
			"attempt": attempt,
		}

		// Log request headers
		for key, values := range req.Header {
			fields[fmt.Sprintf("header_%s", key)] = strings.Join(values, ",")
		}

		// Log request body if present
		if req.Body != nil && req.Body != http.NoBody {
			bodyBytes, err := io.ReadAll(req.Body)
			if err == nil && len(bodyBytes) > 0 {
				fields["body"] = string(bodyBytes)
				// Restore the body for the actual request
				req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}
		}

		logger.WithFields(fields).Debugf("HTTP Request")
	}
}

// CustomTextFormatter is a custom logrus formatter
type CustomTextFormatter struct {
	TimestampFormat  string
	CallerPrettyfier func(*runtime.Frame) (string, string)
}

// Format implements the logrus.Formatter interface
func (f *CustomTextFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var b *bytes.Buffer
	if entry.Buffer != nil {
		b = entry.Buffer
	} else {
		b = &bytes.Buffer{}
	}

	timestamp := entry.Time.Format(f.TimestampFormat)
	fmt.Fprintf(b, "ts=%s ", timestamp)

	if entry.HasCaller() {
		fmt.Fprintf(b, "caller=%s:%d ", FormatFilePath(entry.Caller.File), entry.Caller.Line)
	}

	fmt.Fprintf(b, "level=%s msg=%s", entry.Level, entry.Message)

	for key, value := range entry.Data {
		fmt.Fprintf(b, " %s=%v", key, value)
	}

	b.WriteByte('\n')
	return b.Bytes(), nil
}

// Hook to redirect logs with message starting with [DEBUG] from INFO to DEBUG level
type DebugLevelHook struct {
	Logger *logrus.Logger
}

func (hook *DebugLevelHook) Fire(entry *logrus.Entry) error {
	if entry.Level == logrus.InfoLevel && strings.HasPrefix(entry.Message, "[DEBUG]") {
		// remove [debug] in message
		newMessage := strings.TrimPrefix(entry.Message, "[DEBUG] ")

		// keep original entry metadata
		hook.Logger.WithFields(entry.Data).Debug(newMessage)
	}
	if entry.Level == logrus.InfoLevel && strings.HasPrefix(entry.Message, "[ERR]") {
		// remove [debug] in message
		newMessage := strings.TrimPrefix(entry.Message, "[ERR] ")

		// keep original entry metadata
		hook.Logger.WithFields(entry.Data).Error(newMessage)
	}
	return nil
}

func (hook *DebugLevelHook) Levels() []logrus.Level {
	return []logrus.Level{logrus.InfoLevel}
}

// Custom Writer to block INFO messages containg [DEBUG] in message
type CustomWriter struct {
	Writer io.Writer
}

func (cw *CustomWriter) Write(p []byte) (n int, err error) {
	message := string(p)
	// supporting text and json formatter
	if strings.Contains(message, "[DEBUG]") && (strings.Contains(message, "level=info") || strings.Contains(message, "\"level\":\"info\"")) {
		return len(p), nil
	}
	if strings.Contains(message, "[ERR]") && (strings.Contains(message, "level=info") || strings.Contains(message, "\"level\":\"info\"")) {
		return len(p), nil
	}
	return cw.Writer.Write(p)
}

// SetupLoggers creates and configures all loggers (logrus, go-kit, and lego slog).
// Returns the go-kit logger and logrus logger.
func SetupLoggers(logLevel, logFormat string) (log.Logger, *logrus.Logger) {
	// Setup logrus logger
	logrusLogger := logrus.New()
	logrusLogger.SetReportCaller(true)

	parsedLogLevel, err := logrus.ParseLevel(logLevel)
	if err != nil {
		parsedLogLevel = logrus.InfoLevel
	}
	logrusLogger.SetLevel(parsedLogLevel)

	if logFormat == "json" {
		logrusLogger.SetFormatter(UTCFormatter{Formatter: &logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05.000Z",
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime: "ts",
				logrus.FieldKeyFile: "caller",
			},
			CallerPrettyfier: func(f *runtime.Frame) (string, string) {
				return "", fmt.Sprintf("%s:%d", FormatFilePath(f.File), f.Line)
			},
		}})
	} else {
		logrusLogger.SetFormatter(&CustomTextFormatter{
			TimestampFormat: "2006-01-02T15:04:05.000Z",
		})
	}

	logrusLogger.SetOutput(&CustomWriter{Writer: os.Stdout})
	logrusLogger.AddHook(&DebugLevelHook{Logger: logrusLogger})

	// Setup go-kit logger
	var logger log.Logger
	if logFormat == "json" {
		logger = log.NewJSONLogger(log.NewSyncWriter(os.Stdout))
	} else {
		logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout))
	}
	logger = log.With(logger, "ts", log.DefaultTimestampUTC, "caller", log.Caller(5))

	// Parse log level for both go-kit and slog
	var slogLevel slog.Level
	switch logLevel {
	case "debug":
		logger = level.NewFilter(logger, level.AllowDebug())
		slogLevel = slog.LevelDebug
	case "info":
		logger = level.NewFilter(logger, level.AllowInfo())
		slogLevel = slog.LevelInfo
	case "warn":
		logger = level.NewFilter(logger, level.AllowWarn())
		slogLevel = slog.LevelWarn
	case "error":
		logger = level.NewFilter(logger, level.AllowError())
		slogLevel = slog.LevelError
	default:
		logger = level.NewFilter(logger, level.AllowInfo())
		slogLevel = slog.LevelInfo
	}

	// Setup lego logger with slog
	// Use ReplaceAttr to output lowercase level names for consistency
	replaceAttr := func(groups []string, a slog.Attr) slog.Attr {
		if a.Key == slog.LevelKey {
			level := a.Value.Any().(slog.Level)
			a.Value = slog.StringValue(strings.ToLower(level.String()))
		}
		return a
	}

	var slogHandler slog.Handler
	if logFormat == "json" {
		slogHandler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slogLevel, ReplaceAttr: replaceAttr})
	} else {
		slogHandler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slogLevel, ReplaceAttr: replaceAttr})
	}
	legoLog.SetDefault(slog.New(slogHandler))

	return logger, logrusLogger
}
