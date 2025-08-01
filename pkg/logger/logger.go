package logger

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

// Options for Logger
type Options struct {
	// Enable Debug loglevel, default Info
	Debug bool
}

// NewConsoleLogger outputs logs to stdout in a pretty format, not very efficient
func NewConsoleLogger(opts Options) Logger {
	output := zerolog.ConsoleWriter{Out: os.Stdout, NoColor: true, TimeFormat: time.RFC3339}

	output.FormatLevel = func(i interface{}) string {
		return strings.ToUpper(fmt.Sprintf("| %-6s|", i))
	}

	output.FormatMessage = func(i interface{}) string {
		return fmt.Sprintf("message: %s |", i)
	}

	output.FormatFieldName = func(i interface{}) string {
		return fmt.Sprintf(" %s: ", i)
	}

	output.FormatFieldValue = func(i interface{}) string {
		return fmt.Sprintf("%s |", i)
	}

	if opts.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	return Logger{zerolog.New(output).With().Timestamp().Logger()}
}

// NewJSONLogger outputs logs to stdout in json format
func NewJSONLogger(opts Options) Logger {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	if opts.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
	return Logger{zerolog.New(os.Stdout).With().Timestamp().Logger()}
}
