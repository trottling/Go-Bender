package windows

type driver struct {
	driver struct {
		Id       string   `json:"Id"`
		Tags     []string `json:"Tags"`
		Verified string   `json:"Verified"`
		Author   string   `json:"Author"`
		Created  string   `json:"Created"`
		MitreID  string   `json:"MitreID"`
		Category string   `json:"Category"`
		Commands struct {
			Command         string `json:"Command"`
			Description     string `json:"Description"`
			Usecase         string `json:"Usecase"`
			Privileges      string `json:"Privileges"`
			OperatingSystem string `json:"OperatingSystem"`
		} `json:"Commands"`
		Resources       []string      `json:"Resources"`
		Detection       []interface{} `json:"Detection"`
		Acknowledgement struct {
			Person string `json:"Person"`
			Handle string `json:"Handle"`
		} `json:"Acknowledgement"`
		KnownVulnerableSamples []struct {
			Filename         string `json:"Filename"`
			MD5              string `json:"MD5"`
			SHA1             string `json:"SHA1"`
			SHA256           string `json:"SHA256"`
			Signature        string `json:"Signature"`
			Date             string `json:"Date"`
			Publisher        string `json:"Publisher"`
			Company          string `json:"Company"`
			Description      string `json:"Description"`
			Product          string `json:"Product"`
			ProductVersion   string `json:"ProductVersion"`
			FileVersion      string `json:"FileVersion"`
			MachineType      string `json:"MachineType"`
			OriginalFilename string `json:"OriginalFilename"`
			Imphash          string `json:"Imphash"`
			Authentihash     struct {
				MD5    string `json:"MD5"`
				SHA1   string `json:"SHA1"`
				SHA256 string `json:"SHA256"`
			} `json:"Authentihash"`
			RichPEHeaderHash struct {
				MD5    string `json:"MD5"`
				SHA1   string `json:"SHA1"`
				SHA256 string `json:"SHA256"`
			} `json:"RichPEHeaderHash"`
			Sections struct {
				Text struct {
					Entropy     float64 `json:"Entropy"`
					VirtualSize string  `json:"Virtual Size"`
				} `json:".text"`
				Rdata struct {
					Entropy     float64 `json:"Entropy"`
					VirtualSize string  `json:"Virtual Size"`
				} `json:".rdata"`
				Data struct {
					Entropy     float64 `json:"Entropy"`
					VirtualSize string  `json:"Virtual Size"`
				} `json:".data"`
				Pdata struct {
					Entropy     float64 `json:"Entropy"`
					VirtualSize string  `json:"Virtual Size"`
				} `json:".pdata"`
				INIT struct {
					Entropy     float64 `json:"Entropy"`
					VirtualSize string  `json:"Virtual Size"`
				} `json:"INIT"`
			} `json:"Sections"`
			MagicHeader       string   `json:"MagicHeader"`
			CreationTimestamp string   `json:"CreationTimestamp"`
			InternalName      string   `json:"InternalName"`
			Copyright         string   `json:"Copyright"`
			Imports           []string `json:"Imports"`
			ExportedFunctions string   `json:"ExportedFunctions"`
			ImportedFunctions []string `json:"ImportedFunctions"`
			Signatures        []struct {
				CertificatesInfo string `json:"CertificatesInfo"`
				SignerInfo       string `json:"SignerInfo"`
				Certificates     []struct {
					Subject                string `json:"Subject"`
					ValidFrom              string `json:"ValidFrom"`
					ValidTo                string `json:"ValidTo"`
					Signature              string `json:"Signature"`
					SignatureAlgorithmOID  string `json:"SignatureAlgorithmOID"`
					IsCertificateAuthority bool   `json:"IsCertificateAuthority"`
					SerialNumber           string `json:"SerialNumber"`
					Version                int    `json:"Version"`
					TBS                    struct {
						MD5    string `json:"MD5"`
						SHA1   string `json:"SHA1"`
						SHA256 string `json:"SHA256"`
						SHA384 string `json:"SHA384"`
					} `json:"TBS"`
				} `json:"Certificates"`
				Signer []struct {
					SerialNumber string `json:"SerialNumber"`
					Issuer       string `json:"Issuer"`
					Version      int    `json:"Version"`
				} `json:"Signer"`
			} `json:"Signatures"`
			LoadsDespiteHVCI string `json:"LoadsDespiteHVCI"`
		} `json:"KnownVulnerableSamples"`
	}
}

func (s *WinScanner) CheckDrivers() {
	s.GetDriversDB()
}
func (s *WinScanner) GetDriversDB() {}
func (s *WinScanner) ScanDrivers()  {}
