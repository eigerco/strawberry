package log

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// Logger is an instance of zerolog.Logger
type Logger struct {
	zerolog.Logger
}

type LoggerType uint8

const (
	ConsoleLogger LoggerType = iota
	JSONLogger
)

var (
	Root     zerolog.Logger
	Internal zerolog.Logger
	Network  zerolog.Logger
	VM       zerolog.Logger
)

// Options for Logger
type Options struct {
	// Enable Debug loglevel, default Info
	LogLevel zerolog.Level
	Type     LoggerType
}

func ParseLogLevel(loglevel string) (zerolog.Level, error) {
	return zerolog.ParseLevel(loglevel)
}

func Init(opts Options) {

	switch opts.Type {
	case ConsoleLogger:
		cw := newConsoleWriter()
		Root = zerolog.New(cw).Level(opts.LogLevel).
			With().Timestamp().Logger()
		Internal = Root.With().Str("component", "internal").Logger()
		Network = Root.With().Str("component", "network").Logger()
		VM = Root.With().Str("component", "vm").Logger()
	default:
		Root = zerolog.New(os.Stdout).Level(opts.LogLevel).
			With().Timestamp().Logger()
		Internal = Root.With().Str("component", "internal").Logger()
		Network = Root.With().Str("component", "network").Logger()
		VM = Root.With().Str("component", "vm").Logger()

	}
}

func newConsoleWriter() zerolog.ConsoleWriter {
	cw := zerolog.ConsoleWriter{Out: os.Stdout, NoColor: true, TimeFormat: time.RFC3339}

	cw.FormatLevel = func(i interface{}) string {
		return strings.ToUpper(fmt.Sprintf("| %-6s|", i))
	}

	cw.FormatMessage = func(i interface{}) string {
		return fmt.Sprintf("message: \"%s\" |", i)
	}

	cw.FormatFieldName = func(i interface{}) string {
		return fmt.Sprintf("\"%s\": ", i)
	}

	cw.FormatFieldValue = func(i interface{}) string {
		return fmt.Sprintf("\"%s\" |", i)
	}

	cw.FormatErrFieldValue = func(i interface{}) string {
		return fmt.Sprintf(" %s |", i)
	}
	return cw
}
