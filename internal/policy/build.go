package policy

import (
	"dev-orchestrator/internal/contracts"
	"path"
)

// BuildPath identifies the single permitted local build. Image-only plans have
// no build path and cannot enter the M07 build adapter.
func BuildPath(p contracts.ConfigurationPlan) (string, error) {
	if ValidatePlan(p) != nil {
		return "", ErrDenied
	}
	for _, s := range p.Services {
		if s.Build != nil {
			return path.Join(s.Build.Context, s.Build.Dockerfile), nil
		}
	}
	return "", ErrDenied
}
