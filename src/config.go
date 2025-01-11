package src

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	Keys struct {
		VulnersApiKey string `json:"vulners_api_key"`
	} `json:"keys"`
	PortScanner struct {
		Silent        bool   `json:"silent"`
		Retries       int    `json:"retries"`
		Timeout       int    `json:"timeout"`
		Ports         string `json:"ports"`
		ExcludePorts  string `json:"exclude_ports"`
		Threads       int    `json:"threads"`
		StatsInterval int    `json:"stats_interval"`
		ScanType      string `json:"scan_type"`
		Proxy         string `json:"proxy"`
		ProxyAuth     string `json:"proxy_auth"`
	} `json:"port_scanner"`
}

func (c *Config) Read(path string) error {
	configFile, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to read Сonfig: %v", err)
	}
	defer configFile.Close()

	jsonParser := json.NewDecoder(configFile)
	if err = jsonParser.Decode(c); err != nil {
		return fmt.Errorf("failed to parse Сonfig: %v", err)
	}

	c.Keys.VulnersApiKey = strings.TrimSpace(c.Keys.VulnersApiKey)

	return nil
}
