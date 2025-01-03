package main

import log "github.com/sirupsen/logrus"

type Scanner struct {
	config Config
	args   Args
	log    *log.Logger
}

func (scanner *Scanner) Init() error {
	var err error

	// Logger
	scanner.log = GetLogger()

	// Run arguments
	scanner.args = Args{}
	if err = scanner.args.Get(); err != nil {
		return err
	}

	// Json config from file
	scanner.config = Config{}
	if err = scanner.config.Read(scanner.args.ConfigPath); err != nil {
		return err
	}

	return nil
}

func (scanner *Scanner) Scan() {
	// Initial scanner
	if err := scanner.Init(); err != nil {
		scanner.log.Fatal(err)
	}
}
