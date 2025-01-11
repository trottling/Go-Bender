package src

import (
	"Go-Bender/src/modules/multi_platform"
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

func (scanner *Scanner) LoadPortsDB() error {

	file, err := os.Open(scanner.args.PortsPath)
	if err != nil {
		return fmt.Errorf("failed to open ports CSV: %s", err)
	}

	defer file.Close()
	fileScanner := bufio.NewScanner(file)

	var portInfos []*multi_platform.PortInfo
	var parts []string

	for fileScanner.Scan() {
		parts = strings.Split(fileScanner.Text(), ",")

		if len(parts) != 12 {
			continue
		}
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}

		portInfos = append(portInfos, &multi_platform.PortInfo{
			ServiceName:       parts[0],
			PortNumber:        port,
			TransportProtocol: parts[2],
			Description:       parts[3],
			Assignee:          parts[4],
			Contact:           parts[5],
			RegistrationDate:  parts[6],
			ModificationDate:  parts[7],
			Reference:         parts[8],
			ServiceCode:       parts[9],
			UnauthorizedUse:   parts[10],
			AssignmentNotes:   parts[11],
		})
	}

	scanner.portsInfo = portInfos
	return nil
}

func (scanner *Scanner) LoadScannerOptions() runner.Options {
	return runner.Options{
		Silent:       scanner.config.PortScanner.Silent,
		Retries:      scanner.config.PortScanner.Retries,
		Timeout:      scanner.config.PortScanner.Timeout,
		Ports:        scanner.config.PortScanner.Ports,
		ExcludePorts: scanner.config.PortScanner.ExcludePorts,
		Threads:      scanner.config.PortScanner.Threads,
		ScanType:     scanner.config.PortScanner.ScanType,
		Proxy:        scanner.config.PortScanner.Proxy,
		ProxyAuth:    scanner.config.PortScanner.ProxyAuth,
	}
}
