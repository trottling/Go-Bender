package src

import (
	"Go-Bender/src/modules/multi_platform"
	"fmt"
	"os"

	"github.com/gocarina/gocsv"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

func (scanner *Scanner) LoadPortsDB() error {
	file, err := os.Open(scanner.args.PortsPath)
	if err != nil {
		return fmt.Errorf("failed to open ports CSV: %s", err)
	}

	defer file.Close()

	var portInfos []*multi_platform.PortInfo
	if err := gocsv.UnmarshalFile(file, &portInfos); err != nil {
		return fmt.Errorf("failed to unmarshal ports CSV: %s", err)
	}

	scanner.portsInfo = portInfos
	return nil
}

func (scanner *Scanner) LoadScannerOptions() runner.Options {
	return runner.Options{
		Host:         goflags.StringSlice{""},
		OnResult:     nil,
		Silent:       scanner.config.PortScanner.Silent,
		Retries:      scanner.config.PortScanner.Retries,
		Timeout:      scanner.config.PortScanner.Timeout,
		Ports:        scanner.config.PortScanner.Ports,
		ExcludePorts: scanner.config.PortScanner.ExcludePorts,
		Threads:      scanner.config.PortScanner.Threads,
		ScanType:     scanner.config.PortScanner.ScanType,
		Proxy:        scanner.config.PortScanner.Proxy,
		ProxyAuth:    scanner.config.PortScanner.ProxyAuth,
	}
}
