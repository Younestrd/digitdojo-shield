package nftables

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// Runner executes nft without a shell. Implementations must preserve argument
// boundaries and pass batch programs through standard input.
type Runner interface {
	Run(context.Context, []string, []byte) ([]byte, error)
}

type CommandRunner struct {
	Path string
}

func (r CommandRunner) Run(ctx context.Context, args []string, input []byte) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("nftables command requires a non-nil context")
	}
	if r.Path == "" {
		return nil, fmt.Errorf("nftables executable path is required")
	}
	command := exec.CommandContext(ctx, r.Path, args...)
	command.Stdin = bytes.NewReader(input)
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("run nft %v: %w: %s", args, err, bytes.TrimSpace(output))
	}
	return output, nil
}
