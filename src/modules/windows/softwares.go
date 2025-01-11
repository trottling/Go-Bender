package windows

import (
	"fmt"

	wapi "github.com/iamacarpet/go-win64api"
	"github.com/iamacarpet/go-win64api/shared"
)

func (s *WinScanner) ScanSoftware() {
	s.wg.Add(1)
	defer s.wg.Done()
	_, ok := s.GetSoftwareList()
	if !ok {
		return
	}

}

func (s *WinScanner) GetSoftwareList() ([]shared.Software, bool) {
	sw, err := wapi.InstalledSoftwareList()
	if err != nil {
		s.Result.ScanErrors = append(s.Result.ScanErrors, fmt.Sprintf("Error getting installed software list: %s", err.Error()))
		return nil, false
	}

	var softList []shared.Software

	for _, s := range sw {
		if s.DisplayName != "" && s.DisplayVersion != "" {
			softList = append(softList, s)
		}
	}

	if len(softList) == 0 {
		s.Result.ScanErrors = append(s.Result.ScanErrors, "Error getting installed software list: No software found")
		return nil, false
	}

	if len(softList) > 500 {
		softList = softList[:500]
	}

	return softList, true
}
