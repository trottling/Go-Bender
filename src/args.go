package src

import (
	"fmt"

	"github.com/alexflint/go-arg"
)

type Args struct {
	ConfigPath string `arg:"required,-c,--config" help:"config file path"`
}

func (args *Args) Get() error {
	if err := arg.Parse(args); err != nil {
		return fmt.Errorf("arguments parse error: %w", err)
	}
	return nil
}
