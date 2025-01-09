package src

import (
	"fmt"
	"os"

	"github.com/gocarina/gocsv"
)

// PortInfo struct (correct field names)
type PortInfo struct {
	ServiceName       string `csv:"Service Name"`
	PortNumber        int    `csv:"Port Number"`
	TransportProtocol string `csv:"Transport Protocol"`
	Description       string `csv:"Description"`
	Assignee          string `csv:"Assignee"`
	Contact           string `csv:"Contact"`
	RegistrationDate  string `csv:"Registration Date"`
	ModificationDate  string `csv:"Modification Date"`
	Reference         string `csv:"Reference"`
	ServiceCode       string `csv:"Service Code"`
	UnauthorizedUse   string `csv:"Unauthorized Use Reported"`
	AssignmentNotes   string `csv:"Assignment Notes"`
}

func (scanner *Scanner) LoadPortsDB() error {
	file, err := os.Open(scanner.args.PortsPath)
	if err != nil {
		return fmt.Errorf("failed to open ports CSV: %s", err)
	}

	defer file.Close()

	var portInfos []*PortInfo
	if err := gocsv.UnmarshalFile(file, &portInfos); err != nil {
		return fmt.Errorf("failed to unmarshal ports CSV: %s", err)
	}

	scanner.ports = portInfos
	return nil
}
