package src

import (
	"Go-Bender/src/modules/linux"
	"Go-Bender/src/modules/multi_platform"
	"Go-Bender/src/modules/windows"
	"errors"
	"runtime"
	"sync"

	"github.com/projectdiscovery/naabu/v2/pkg/runner"
	log "github.com/sirupsen/logrus"
)

type Scanner struct {
	wg                 sync.WaitGroup
	log                *log.Logger
	portsInfo          []*multi_platform.PortInfo
	config             Config
	args               Args
	portScannerOptions runner.Options
	WinScanner         windows.WinScanner
	LinuxScanner       linux.LinScanner
	MultiScanner       multi_platform.MultiScanner
	ScanResult         ScanResult
}

type ScanResult struct {
	Multi   multi_platform.MultiScannerResult `json:"Multi"`
	Windows windows.WinScannerResult          `json:"Windows,omitempty"`
	Linux   linux.LinScannerResult            `json:"Linux,omitempty"`
}

func (scanner *Scanner) Init() error {
	var err error

	// Logger
	scanner.log = scanner.GetLogger()
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

	// Ports info database
	scanner.log.Info("Loading ports database")
	if err = scanner.LoadPortsDB(); err != nil {
		return err
	}

	// Load port scanner options
	scanner.log.Info("Loading port scanner options")
	scanner.portScannerOptions = scanner.LoadScannerOptions()

	scanner.WinScanner.VulnersKey = scanner.config.Keys.VulnersApiKey
	scanner.LinuxScanner.VulnersKey = scanner.config.Keys.VulnersApiKey

	scanner.MultiScanner.PortsScannerOptions = scanner.portScannerOptions
	scanner.MultiScanner.PortsInfo = scanner.portsInfo

	return nil
}

func (scanner *Scanner) Scan() {
	// Init scanner
	err := scanner.Init()
	if err != nil {
		scanner.log.Fatal(err)
	}

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
