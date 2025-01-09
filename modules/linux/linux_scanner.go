package linux

type LinScanner struct {
	ScanErrors []string `json:"ScanErrors"`
}

func (s *LinScanner) Scan() {}
