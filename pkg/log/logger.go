package log

import (
	"github.com/rs/zerolog"
	"os"
)

func New() Logger {
	return Logger{
		zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).Level(zerolog.DebugLevel),
	}
}

type Logger struct {
	zerolog.Logger
}
