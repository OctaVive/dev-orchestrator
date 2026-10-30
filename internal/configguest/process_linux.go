//go:build linux

package configguest

import (
	"bytes"
	"context"
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/policy"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// Child is called only by the sealed guest runner's fixed -normalize entry.
func Child() int {
	if os.Geteuid() != 1000 || os.WriteFile("/sys/fs/cgroup/runner/config-parser/cgroup.procs", []byte(strconv.Itoa(os.Getpid())), 0600) != nil {
		return 31
	}
	var in struct{ Dir, Mode, Config string }
	d := json.NewDecoder(io.LimitReader(os.Stdin, 8192))
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil {
		return 32
	}
	p, e := Repository(in.Dir, in.Mode, in.Config)
	if e != nil {
		if errors.Is(e, ErrRead) {
			return 36
		}
		if errors.Is(e, ErrDockerfile) {
			return 37
		}
		return 33
	}
	b, e := json.Marshal(p)
	if e != nil || len(b) > contracts.MaxPlanBytes {
		return 34
	}
	if _, e = os.Stdout.Write(b); e != nil {
		return 35
	}
	return 0
}

type capped struct{ b bytes.Buffer }

func (b *capped) Write(p []byte) (int, error) {
	if len(p) > contracts.MaxPlanBytes-b.b.Len() {
		return 0, io.ErrShortBuffer
	}
	return b.b.Write(p)
}
func Analyze(parent context.Context, dir, mode, config string) (contracts.ConfigurationPlan, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	exe := "/bin/clone-runner"
	b, _ := json.Marshal(struct{ Dir, Mode, Config string }{dir, mode, config})
	cmd := exec.CommandContext(ctx, exe, "-normalize")
	cmd.Stdin = bytes.NewReader(b)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "GOMEMLIMIT=96MiB", "GOMAXPROCS=1"}
	out := &capped{}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	if e := cmd.Run(); e != nil {
		var exit *exec.ExitError
		if errors.As(e, &exit) {
			switch exit.ExitCode() {
			case 31:
				return contracts.ConfigurationPlan{}, errors.New("parser_cgroup_denied")
			case 32:
				return contracts.ConfigurationPlan{}, errors.New("parser_input_denied")
			case 33:
				return contracts.ConfigurationPlan{}, errors.New("parser_configuration_denied")
			case 36:
				return contracts.ConfigurationPlan{}, ErrRead
			case 37:
				return contracts.ConfigurationPlan{}, ErrDockerfile
			case 34:
				return contracts.ConfigurationPlan{}, errors.New("parser_output_denied")
			}
		}
		return contracts.ConfigurationPlan{}, errors.New("parser_process_denied")
	}
	p, e := contracts.DecodeConfiguration[contracts.ConfigurationPlan](bytes.NewReader(out.b.Bytes()))
	if e != nil || policy.ValidatePlan(p) != nil {
		return contracts.ConfigurationPlan{}, ErrDenied
	}
	return p, nil
}
