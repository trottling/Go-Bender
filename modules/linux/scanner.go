package linux

import (
	"fmt"
	"sync"

	"github.com/matishsiao/goInfo"
)

type LinScanner struct {
	wg     sync.WaitGroup
	Result struct {
		Os struct {
			Kernel   string `json:"kernel"`
			Core     string `json:"core"`
			Platform string `json:"platform"`
			OS       string `json:"os"`
		} `json:"Os"`
		Hardware struct {
			Cpu            string `json:"Cpu"`
			Gpu            string `json:"Gpu"`
			Ram            string `json:"Ram"`
			Storage        string `json:"Storage"`
			Virtualization string `json:"Virtualization"`
		} `json:"Hardware"`
		Network struct {
			Local           string `json:"Local IP"`
			Remote          string `json:"Remote IP"`
			FirewallEnabled string `json:"Firewall enabled"`
			MacAddress      string `json:"Mac address"`
		} `json:"Network"`
		ScanErrors []string `json:"ScanErrors"`
	} `json:"Result"`
}

func (s *LinScanner) Scan() {
	s.wg.Add(3)
	go s.HardwareScan()
	go s.NetworkScan()
	go s.NetworkScan()
	s.wg.Wait()
}

func (s *LinScanner) OsScan() {
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

func (s *LinScanner) HardwareScan() {
	defer s.wg.Done()

}
func (s *LinScanner) NetworkScan() {
	defer s.wg.Done()

}
