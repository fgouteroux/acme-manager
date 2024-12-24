package utils

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/sirupsen/logrus"

	"golang.org/x/net/idna"
)

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

// Get sha1 from string
func SHA1Hash(content string) string {
	hash := sha1.New()
	hash.Write([]byte(content))
	return hex.EncodeToString(hash.Sum(nil))
}
