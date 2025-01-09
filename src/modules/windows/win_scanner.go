package windows

import "sync"

type WinScanner struct {
	wg         sync.WaitGroup
	VulnersKey string
	Result     WinScannerResult
}

type WinScannerResult struct {
	Bitlocker  Bitlocker `json:"Bitlocker"`
	ScanErrors []string  `json:"ScanErrors"`
}

func (s *WinScanner) Scan() WinScannerResult {
	go s.BitlockerScan()

	s.wg.Wait()
	return s.Result
}
