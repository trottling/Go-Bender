package src

import (
	"Go-Bender/src/modules/linux"
	"Go-Bender/src/modules/multi_platform"
	"Go-Bender/src/modules/windows"
	"errors"
	"runtime"
	"sync"

	log "github.com/sirupsen/logrus"
)

type Scanner struct {
	wg           sync.WaitGroup
	config       Config
	args         Args
	log          *log.Logger
	WinScanner   windows.WinScanner
	LinuxScanner linux.LinScanner
	MultiScanner multi_platform.MultiScanner
	ScanResult   ScanResult
}

type ScanResult struct {
	Multi   multi_platform.MultiScannerResult `json:"Multi"`
	Windows windows.WinScannerResult          `json:"Windows,omitempty"`
	Linux   linux.LinScannerResult            `json:"Linux,omitempty"`
}

func (scanner *Scanner) Init() error {
	var err error

	// Logger
	scanner.log = GetLogger()
	scanner.log.Info("Initializing scanner...")

	// Run arguments
	scanner.log.Info("Loading run arguments")
	scanner.args = Args{}
	if err = scanner.args.Get(); err != nil {
		return err
	}

	// Json config from file
	scanner.log.Info("Loading config")
	scanner.config = Config{}
	if err = scanner.config.Read(scanner.args.ConfigPath); err != nil {
		return err
	}

	// Check Vulners key
	scanner.log.Info("Checking vulners key")
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
	// Init scanner
	err := scanner.Init()
	if err != nil {
		scanner.log.Fatal(err)
	}

	scanner.WinScanner.VulnersKey = scanner.config.Keys.VulnersApiKey
	scanner.LinuxScanner.VulnersKey = scanner.config.Keys.VulnersApiKey

	// Multiplatform scan
	scanner.ScanResult.Multi = scanner.MultiScanner.Scan()

	switch runtime.GOOS {
	case "windows":
		scanner.ScanResult.Windows = scanner.WinScanner.Scan()
	case "linux":
		scanner.ScanResult.Linux = scanner.LinuxScanner.Scan()
	}

	scanner.wg.Wait()
}
