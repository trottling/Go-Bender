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
	Threads struct {
		PortScanner int `json:"port_scanner"`
		Network     int `json:"network"`
	} `json:"threads"`
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
