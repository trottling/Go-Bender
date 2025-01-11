package src

import (
	"os"

	log "github.com/sirupsen/logrus"
)

func (scanner *Scanner) GetLogger() *log.Logger {
	Log := log.New()
	Log.SetOutput(os.Stdout)
	Log.SetFormatter(&log.TextFormatter{
		ForceColors:  true,
		PadLevelText: true,
	})
	return Log
}
