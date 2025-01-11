package multi_platform

import (
	"context"
	"fmt"
	"net"

	"github.com/go-resty/resty/v2"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

type Ports struct {
	Local    []PortInfo `json:"Local opened ports"`
	External []PortInfo `json:"External opened ports"`
}

type PortInfo struct {
	PortNumber        int    `csv:"Port Number" json:"Port Number"`
	ServiceName       string `csv:"Service Name" json:"Service Name,omitempty"`
	TransportProtocol string `csv:"Transport Protocol" json:"Transport Protocol,omitempty"`
	Description       string `csv:"Description" json:"Description,omitempty"`
	Assignee          string `csv:"Assignee" json:"Assignee,omitempty"`
	Contact           string `csv:"Contact" json:"Contact,omitempty"`
	RegistrationDate  string `csv:"Registration Date" json:"Registration Date,omitempty"`
	ModificationDate  string `csv:"Modification Date" json:"Modification Date,omitempty"`
	Reference         string `csv:"Reference" json:"Reference,omitempty"`
	ServiceCode       string `csv:"Service Code" json:"Service Code,omitempty"`
	UnauthorizedUse   string `csv:"Unauthorized Use Reported" json:"Unauthorized Use,omitempty"`
	AssignmentNotes   string `csv:"Assignment Notes" json:"Assignment Notes,omitempty"`
}

func (s *MultiScanner) PortsScan() {
	go s.LocalPortScan()
	go s.ExternalPortScan()

}

func (s *MultiScanner) LocalPortScan() {
	s.wg.Add(1)
	Ip, err := GetLocalIP()
	if err != nil {
		s.Result.ScanErrors = append(s.Result.ScanErrors, fmt.Sprintf("Local ports scan failed: %s", err))
		return
	}

	options := s.PortsScannerOptions
	options.Host = goflags.StringSlice{Ip}
	options.OnResult = func(hr *result.HostResult) {
		for _, port := range hr.Ports {
			s.Result.Ports.Local = append(s.Result.Ports.Local, s.GetPortInfo(port.Port))
		}
		s.wg.Done()
	}

	Runner, err := runner.NewRunner(&options)
	if err != nil {
		s.Result.ScanErrors = append(s.Result.ScanErrors, fmt.Sprintf("Local ports scan failed: %s", err))
	}
	defer Runner.Close()

	err = Runner.RunEnumeration(context.Background())
	if err != nil {
		s.Result.ScanErrors = append(s.Result.ScanErrors, fmt.Sprintf("Local ports scan failed: %s", err))
		return
	}
}

func GetLocalIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", fmt.Errorf("error getting local address: %s", err.Error())
	}
	if conn == nil {
		return "", fmt.Errorf("error getting local address: %s", err.Error())
	}
	defer conn.Close()

	return conn.LocalAddr().(*net.UDPAddr).IP.String(), nil
}

func (s *MultiScanner) ExternalPortScan() {
	s.wg.Add(1)
	Ip, err := GetRemoteIP()

	if err != nil {
		s.Result.ScanErrors = append(s.Result.ScanErrors, fmt.Sprintf("Extenal ports scan failed: %s", err))
		return
	}

	options := s.PortsScannerOptions
	options.Host = goflags.StringSlice{Ip}

	Runner, err := runner.NewRunner(&options)
	if err != nil {
		s.Result.ScanErrors = append(s.Result.ScanErrors, fmt.Sprintf("Extenal ports scan failed: %s", err))
	}
	defer Runner.Close()

	err = Runner.RunEnumeration(context.Background())
	if err != nil {
		s.Result.ScanErrors = append(s.Result.ScanErrors, fmt.Sprintf("Extenal ports scan failed: %s", err))
		return
	}
}

func GetRemoteIP() (string, error) {
	type ipify struct {
		Ip string `json:"ip"`
	}

	client := resty.New()
	resp, err := client.R().SetResult(&ipify{}).Get("https://api64.ipify.org?format=json")
	if err != nil {
		return "", fmt.Errorf("error getting remote address: %s", err.Error())
	}

	return resp.Result().(*ipify).Ip, nil
}

func (s *MultiScanner) GetPortInfo(sPort int) PortInfo {
	for _, port := range s.PortsInfo {
		if port.PortNumber == sPort {
			return *port
		}
	}
	return PortInfo{PortNumber: sPort,
		Description: fmt.Sprintf("Port %d not found", sPort)}
}
