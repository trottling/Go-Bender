package windows

import (
	"sync"
	"time"
)

type WinScanner struct {
	wg         sync.WaitGroup
	VulnersKey string
	Result     WinScannerResult
}

type WinScannerResult struct {
	Bitlocker  Bitlocker `json:"Bitlocker"`
	Firewall   Firewall  `json:"Firewall"`
	ScanErrors []string  `json:"ScanErrors,omitempty"`
}

func (s *WinScanner) Scan() WinScannerResult {
	go s.BitlockerScan()
	go s.CheckFirewall()

	time.Sleep(1 * time.Second)

	s.wg.Wait()
	return s.Result
}
