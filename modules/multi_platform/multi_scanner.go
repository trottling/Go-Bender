package multi_platform

import "sync"

type MultiScanner struct {
	wg     sync.WaitGroup
	Result struct {
		Os         Os       `json:"Os"`
		Hardware   Hardware `json:"Hardware"`
		Network    Network  `json:"Network"`
		ScanErrors []string `json:"ScanErrors"`
	}
}

func (s *MultiScanner) Scan() {
	go s.OsScan()
	go s.HardwareScan()
	go s.NetworkScan()

	s.wg.Wait()
}
