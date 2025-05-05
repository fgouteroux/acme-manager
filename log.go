package main

import (
	"bytes"
	"fmt"
	"runtime"

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
	b.WriteString(fmt.Sprintf("ts=%s ", timestamp))

	if entry.HasCaller() {
		b.WriteString(fmt.Sprintf("caller=%s:%d ", utils.FormatFilePath(entry.Caller.File), entry.Caller.Line))
	}

	b.WriteString(fmt.Sprintf("level=%s msg=%s", entry.Level, entry.Message))

	for key, value := range entry.Data {
		b.WriteString(fmt.Sprintf(" %s=%v", key, value))
	}

	b.WriteByte('\n')
	return b.Bytes(), nil
}
