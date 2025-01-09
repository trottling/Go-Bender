package linux

type LinScanner struct {
	VulnersKey string
	Result     LinScannerResult
}

type LinScannerResult struct {
	ScanErrors []string `json:"ScanErrors"`
}

func (s *LinScanner) Scan() LinScannerResult {
	return s.Result
}
