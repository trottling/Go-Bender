package multi_platform

import (
	"context"
	"fmt"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

type Ports struct {
	Local    []Ports `json:"Local opened ports"`
	External []Ports `json:"External opened ports"`
}

type Port struct {
	ServiceName       string `json:"Service Name,,omitempty"`
	PortNumber        int    `json:"Port Number"`
	TransportProtocol string `json:"Transport Protocol,omitempty"`
	Description       string `json:"Description,omitempty"`
	Assignee          string `json:"Assignee,omitempty"`
	Contact           string `json:"Contact,omitempty"`
	RegistrationDate  string `json:"Registration Date,omitempty"`
	ModificationDate  string `json:"Modification Date,omitempty"`
	Reference         string `json:"Reference,omitempty"`
	ServiceCode       string `json:"Service Code,omitempty"`
	UnauthorizedUse   string `json:"Unauthorized Use Reported,omitempty"`
	AssignmentNotes   string `json:"Assignment Notes,omitempty"`
}

func (s *MultiScanner) PortsScan() {
	go s.LocalPortScan()
	go s.ExternalPortScan()

}
func (s *MultiScanner) LocalPortScan() {
	s.wg.Add(1)

	options := runner.Options{
		Host:     goflags.StringSlice{"scanme.sh"},
		ScanType: "s",
		OnResult: func(hr *result.HostResult) {
			s.wg.Done()

		},
		Ports: "80",
	}

	naabuRunner, err := runner.NewRunner(&options)
	if err != nil {
		s.Result.ScanErrors = append(s.Result.ScanErrors, fmt.Sprintf("Local ports scan failed: %s", err))
	}
	defer naabuRunner.Close()

	err := naabuRunner.RunEnumeration(context.Background())
	if err != nil {
		return
	}
}

func (s *MultiScanner) ExternalPortScan() {
	s.wg.Add(1)
	defer s.wg.Done()
}
