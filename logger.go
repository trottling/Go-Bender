package main

import (
	"os"

	log "github.com/sirupsen/logrus"
)

func GetLogger() *log.Logger {
	Log := log.New()
	Log.SetOutput(os.Stdout)
	Log.SetFormatter(&log.TextFormatter{
		ForceColors:     true,
		TimestampFormat: "15-04-05"})
	return Log
}
