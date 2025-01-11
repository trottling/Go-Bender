package multi_platform

import (
	"bytes"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/jaypipes/ghw"
)

type Hardware struct {
	Cpu            string `json:"Cpu"`
	Gpu            string `json:"Gpu"`
	Ram            string `json:"Ram"`
	Storage        string `json:"Storage"`
	Virtualization string `json:"Virtualization,omitempty"`
}

func (s *MultiScanner) HardwareScan() {
	if runtime.GOOS == "windows" {
		go s.CheckVirtualization()
	}
	go s.GetMachineComponents()
}

func (s *MultiScanner) CheckVirtualization() {
	s.wg.Add(1)
	defer s.wg.Done()

	cmd := exec.Command("powershell", "Get-ComputerInfo -property HyperVisorPresent")

	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		s.Result.ScanErrors = append(s.Result.ScanErrors, fmt.Sprintf("Error checking virtualization: %s", err))
	}

	if bytes.Contains(out.Bytes(), []byte("True")) {
		s.Result.Hardware.Virtualization = "Enabled"
	} else if bytes.Contains(out.Bytes(), []byte("False")) {
		s.Result.Hardware.Virtualization = "Disabled"
	}
}

func (s *MultiScanner) GetMachineComponents() {
	s.wg.Add(1)
	defer s.wg.Done()

	cpu, err := ghw.CPU()
	if err != nil {
		s.Result.ScanErrors = append(s.Result.ScanErrors, fmt.Sprintf("Error getting machine components (CPU): %s", err))
	} else {
		var res []string
		for _, c := range cpu.Processors {
			res = append(res, fmt.Sprintf("%s %s", c.Vendor, c.Model))
		}
		s.Result.Hardware.Cpu = strings.Join(res, " | ")
	}

	gpu, err := ghw.GPU()
	if err != nil {
		s.Result.ScanErrors = append(s.Result.ScanErrors, fmt.Sprintf("Error getting machine components (GPU): %s", err))
	} else {
		var res []string
		for _, g := range gpu.GraphicsCards {
			res = append(res, fmt.Sprintf("%s %s", g.DeviceInfo.Vendor, g.DeviceInfo.Product))
		}
		s.Result.Hardware.Gpu = strings.Join(res, " | ")
	}

	memory, err := ghw.Memory()
	if err != nil {
		s.Result.ScanErrors = append(s.Result.ScanErrors, fmt.Sprintf("Error getting machine components (RAM): %s", err))
	} else {
		s.Result.Hardware.Ram = memory.String()
	}

	storage, err := ghw.Block()
	if err != nil {
		s.Result.ScanErrors = append(s.Result.ScanErrors, fmt.Sprintf("Error getting machine components (Storage): %s", err))
	} else {
		var res []string
		for _, s := range storage.Disks {
			res = append(res, fmt.Sprintf("%s %s %s", s.Name, s.Vendor, s.Model))
		}
		s.Result.Hardware.Storage = strings.Join(res, " | ")
	}
}
