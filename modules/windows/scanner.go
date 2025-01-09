package windows

import (
	"sync"
)

type WinScanner struct {
	wg     sync.WaitGroup
	Result ScanResult
}

type ScanResult struct {
	Os       Os       `json:"Os"`
	Hardware Hardware `json:"Hardware"`
	Network  Network  `json:"Network"`

	ScanErrors []string `json:"ScanErrors"`
}

func (s *WinScanner) Scan() ScanResult {
	s.Result = ScanResult{}

	// System env
	go s.OsScan()
	go s.HardwareScan()
	go s.NetworkScan()

	s.wg.Wait()
	return s.Result
}
