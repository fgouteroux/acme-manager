package main

import (
	"bytes"
	"fmt"
	"io"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/fgouteroux/acme_manager/utils"
)

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
		fmt.Fprintf(b, "caller=%s:%d ", utils.FormatFilePath(entry.Caller.File), entry.Caller.Line)
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
	writer io.Writer
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
	return cw.writer.Write(p)
}
