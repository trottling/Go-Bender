package multi_platform

import (
	"bytes"
	"fmt"
	"os/exec"

	"github.com/jaypipes/ghw"
)

type Hardware struct {
	Cpu            string `json:"Cpu"`
	Gpu            string `json:"Gpu"`
	Ram            string `json:"Ram"`
	Storage        string `json:"Storage"`
	Virtualization string `json:"Virtualization"`
}

func (s *MultiScanner) HardwareScan() {
	go s.CheckVirtualization()
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
		s.Result.Hardware.Cpu = cpu.String()
	}

	gpu, err := ghw.GPU()
	if err != nil {
		s.Result.ScanErrors = append(s.Result.ScanErrors, fmt.Sprintf("Error getting machine components (GPU): %s", err))
	} else {
		s.Result.Hardware.Gpu = gpu.String()
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
		s.Result.Hardware.Storage = storage.String()
	}
}
