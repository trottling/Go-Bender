package windows

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	wapi "github.com/iamacarpet/go-win64api"
	"github.com/matishsiao/goInfo"
)

type Os struct {
	Platform  string `json:"Platform"`
	OS        string `json:"Os"`
	Kernel    string `json:"Kernel"`
	Core      string `json:"Core"`
	Bitlocker struct {
		Drives []BitlockerDrive `json:"Drives"`
	} `json:"Bitlocker"`
}

type BitlockerDrive struct {
	Drive   string `json:"Drive"`
	Status  string `json:"Status"`
	EncPerc string `json:"Encrypted percentage"`
	Flags   string `json:"Encryption flags"`
}

func (s *WinScanner) OsScan() {
	go s.GetOsInfo()
	go s.CheckBitlocker()
}

func (s *WinScanner) GetOsInfo() {
	s.wg.Add(1)
	defer s.wg.Done()

	gi, err := goInfo.GetInfo()
	if err != nil {
		s.Result.ScanErrors = append(s.Result.ScanErrors, fmt.Sprintf("Error getting OS info: %s", err))
	} else {
		s.Result.Os.Kernel = gi.Kernel
		s.Result.Os.Core = gi.Core
		s.Result.Os.Platform = gi.Platform
		s.Result.Os.OS = gi.OS
	}
}

func (s *WinScanner) CheckBitlocker() {
	s.wg.Add(1)
	defer s.wg.Done()

	drives, err := GetLogicalDisksBitlocker()
	if err != nil {
		s.Result.ScanErrors = append(s.Result.ScanErrors, fmt.Sprintf("Error checking bitlocker: %s", err))
		return
	}

	for _, drive := range drives {
		pr, err := wapi.GetBitLockerConversionStatusForDrive(drive)
		if err != nil {
			s.Result.ScanErrors = append(s.Result.ScanErrors, fmt.Sprintf("Error checking bitlocker: Drive %s: %s", drive, err))
			continue
		}
		s.Result.Os.Bitlocker.Drives = append(s.Result.Os.Bitlocker.Drives, BitlockerDrive{
			Drive:   drive,
			Status:  DecryptBitLockerStatus(pr.ConversionStatus),
			EncPerc: strconv.Itoa(int(pr.EncryptionPercentage)),
			Flags:   DecryptBitLockerFlags(pr.EncryptionFlags),
		})
	}
}

func GetLogicalDisksBitlocker() ([]string, error) {
	var drives []string
	for letter := 'A'; letter <= 'Z'; letter++ {
		drive := string(letter) + ":"
		if _, err := os.Stat(drive); err == nil {
			drives = append(drives, drive)
		}
	}
	if len(drives) == 0 {
		return nil, errors.New("no drives found")
	}
	return drives, nil
}

// DecryptBitLockerStatus https://learn.microsoft.com/en-us/windows/win32/secprov/getconversionstatus-win32-encryptablevolume
func DecryptBitLockerStatus(status uint32) string {
	switch status {
	case 0:
		return "Fully decrypted - For a standard hard drive (HDD), the volume is fully decrypted.\nFor a hardware encrypted hard drive (EHDD), the volume is perpetually unlocked"
	case 1:
		return "Fully encrypted - For a standard hard drive (HDD), the volume is fully encrypted.\nFor a hardware encrypted hard drive (EHDD), the volume is not perpetually unlocked."
	case 2:
		return "Encryption in progress - The volume is partially encrypted."
	case 3:
		return "Decryption in progress - The volume is partially encrypted."
	case 4:
		return "Encryption paused - The volume has been paused during the encryption progress. The volume is partially encrypted."
	case 5:
		return "Decryption paused - The volume has been paused during the decryption progress. The volume is partially encrypted."
	default:
		return fmt.Sprintf("Unknown bitlocker status - %s", strconv.Itoa(int(status)))
	}
}

// DecryptBitLockerFlags https://learn.microsoft.com/en-us/windows/win32/secprov/getconversionstatus-win32-encryptablevolume
func DecryptBitLockerFlags(flag uint32) string {
	switch flag {
	case 0x00000001:
		return "Perform volume encryption in data-only encryption mode when starting new encryption process. If encryption has been paused or stopped, calling the Encrypt method effectively resumes conversion and the value of this bit is ignored. This bit only has effect when either the Encrypt or EncryptAfterHardwareTest methods start encryption from the fully decrypted state, decryption in progress state, or decryption paused state. If this bit is zero, meaning that it is not set, when starting new encryption process, then full mode conversion will be performed."
	case 0x00000002:
		return "Perform on-demand wipe of the volume free space. Calling the Encrypt method with this bit set is only allowed when volume is not currently converting or wiping and is in an \"encrypted\" state."
	case 0x00010000:
		return "Perform the requested operation synchronously. The call will block until requested operation has completed or was interrupted. This flag is only supported with the Encrypt method. This flag can be specified when Encrypt is called to resume stopped or interrupted encryption or wiping or when either encryption or wiping is in progress. This allows the caller to resume synchronously waiting until the process is completed or interrupted."
	default:
		return fmt.Sprintf("Unknown encryption flag - %s", strconv.Itoa(int(flag)))
	}
}
