package multi_platform

import (
	"sync"

	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

type MultiScanner struct {
	wg                  sync.WaitGroup
	PortsScannerOptions runner.Options
	PortsInfo           []*PortInfo
	Result              MultiScannerResult
}

type MultiScannerResult struct {
	Os         Os       `json:"Os"`
	Hardware   Hardware `json:"Hardware"`
	Network    Network  `json:"Network"`
	Ports      Ports    `json:"Ports"`
	ScanErrors []string `json:"ScanErrors"`
}

func (s *MultiScanner) Scan() MultiScannerResult {
	go s.OsScan()
	go s.HardwareScan()
	go s.NetworkScan()
	go s.PortsScan()

	s.wg.Wait()
	return s.Result
}
