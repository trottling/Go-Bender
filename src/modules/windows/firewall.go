package windows

import (
	"fmt"

	wapi "github.com/iamacarpet/go-win64api"
)

type Firewall struct {
	Enabled   string         `json:"Firewall enabled"`
	RulesList []FirewallRule `json:"Rules list"`
}

type FirewallRule struct {
	Name            string `json:"Name"`
	Description     string `json:"Description"`
	ApplicationName string `json:"Application name"`
}

func (s *WinScanner) CheckFirewall() {
	s.wg.Add(1)
	defer s.wg.Done()

	rules, err := wapi.FirewallRulesGet()
	if err != nil {
		s.Result.Firewall.Enabled = "unknown"
		s.Result.ScanErrors = append(s.Result.ScanErrors, fmt.Sprintf("Firewall rules could not be found: %s", err.Error()))
		return
	}

	if len(rules) == 0 {
		s.Result.Firewall.Enabled = "false"
		return
	}

	s.Result.Firewall.Enabled = "true"

	for _, rule := range rules {
		s.Result.Firewall.RulesList = append(s.Result.Firewall.RulesList, FirewallRule{
			Name:            rule.Name,
			Description:     rule.Description,
			ApplicationName: rule.ApplicationName,
		})
	}
}
