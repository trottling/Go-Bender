package multi_platform

import (
	"fmt"
	"net"
	"strings"

	"github.com/go-resty/resty/v2"
)

type Network struct {
	Local      string `json:"Local IP"`
	Remote     string `json:"Remote IP"`
	MacAddress string `json:"Mac address"`
}

func (s *MultiScanner) NetworkScan() {
	go s.GetLocalAddress()
	go s.GetRemoteAddress()
	go s.GetMacAddress()
}

func (s *MultiScanner) GetLocalAddress() {
	s.wg.Add(1)
	defer s.wg.Done()

	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		s.Result.ScanErrors = append(s.Result.ScanErrors, fmt.Sprintf("Error getting local address: %s", err.Error()))
		return
	}
	if conn == nil {
		s.Result.ScanErrors = append(s.Result.ScanErrors, "Error getting local address: connection is nil")
		return
	}
	defer conn.Close()

	s.Result.Network.Local = conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func (s *MultiScanner) GetRemoteAddress() {
	s.wg.Add(1)
	defer s.wg.Done()

	type ipify struct {
		Ip string `json:"ip"`
	}

	client := resty.New()
	resp, err := client.R().SetResult(&ipify{}).Get("https://api64.ipify.org?format=json")
	if err != nil {
		s.Result.ScanErrors = append(s.Result.ScanErrors, fmt.Sprintf("Error getting remote address: %s", err.Error()))
		return
	} else {
		s.Result.Network.Remote = resp.Result().(*ipify).Ip
	}

}

func (s *MultiScanner) GetMacAddress() {
	s.wg.Add(1)
	defer s.wg.Done()

	ifas, err := net.Interfaces()
	if err != nil {
		s.Result.ScanErrors = append(s.Result.ScanErrors, fmt.Sprintf("Error getting MAC address: %s", err.Error()))
		return
	}
	var as []string
	for _, ifa := range ifas {
		a := ifa.HardwareAddr.String()
		if a != "" {
			as = append(as, a)
		}
	}
	s.Result.Network.MacAddress = strings.Join(as, ":")
}
