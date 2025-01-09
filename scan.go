package main

import (
	"Go-Bender/modules/linux"
	"Go-Bender/modules/windows"
	"errors"
	"runtime"

	log "github.com/sirupsen/logrus"
)

type Scanner struct {
	config       Config
	args         Args
	log          *log.Logger
	WinScanner   windows.WinScanner
	LinuxScanner linux.LinScanner
}

func (scanner *Scanner) Init() error {
	var err error

	// Logger
	scanner.log = GetLogger()

	// Run arguments
	scanner.args = Args{}
	if err = scanner.args.Get(); err != nil {
		return err
	}

	// Json config from file
	scanner.config = Config{}
	if err = scanner.config.Read(scanner.args.ConfigPath); err != nil {
		return err
	}

	// Check Vulners key
	res, err := CheckVulnersKey(scanner.config.Keys.VulnersApiKey)
	if err != nil {
		return err
	}
	if !res {
		return errors.New("vulners api key is not valid")
	}

	return nil
}

func (scanner *Scanner) Scan() {
	// Initial scanner
	if err := scanner.Init(); err != nil {
		scanner.log.Fatalf("Cannot run scanner: %s", err)
	}

	// Run scan
	switch runtime.GOOS {
	case "linux":
		scanner.LinuxScanner = linux.LinScanner{}
		scanner.LinuxScanner.Scan()
	case "windows":
		scanner.WinScanner = windows.WinScanner{}
		scanner.WinScanner.Scan()
	default:
		scanner.log.Fatalf("Cannot run scanner on this OS: %s", runtime.GOOS)
	}
}
