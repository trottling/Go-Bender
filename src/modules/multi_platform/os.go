package multi_platform

import (
	"fmt"

	"github.com/matishsiao/goInfo"
)

type Os struct {
	Platform string `json:"Platform"`
	OS       string `json:"Os"`
	Kernel   string `json:"Kernel"`
	Core     string `json:"Core"`
}

func (s *MultiScanner) OsScan() {
	defer s.wg.Done()

	gi, err := goInfo.GetInfo()
	if err != nil {
		s.Result.ScanErrors = append(s.Result.ScanErrors, fmt.Sprintf("Error getting OS info: %s", err))
	} else {
		s.Result.Os.Kernel = gi.Kernel
		s.Result.Os.Core = gi.Core
		s.Result.Os.Platform = gi.Platform
		s.Result.Os.OS = gi.OS
	}
}
