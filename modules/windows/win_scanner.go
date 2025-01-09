package windows

import "sync"

type WinScanner struct {
	wg         sync.WaitGroup
	VulnersKey string
	Result     struct {
		Bitlocker  Bitlocker `json:"Bitlocker"`
		ScanErrors []string  `json:"ScanErrors"`
	}
}

func (s *WinScanner) Scan() {
	go s.BitlockerScan()

	s.wg.Wait()
}
