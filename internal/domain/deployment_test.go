package domain

import "testing"

func TestTransitionMatrix(t *testing.T) {
	states := []State{Submitted, Validating, Cloning, Building, Scanning, Approved, Deploying, HealthCheck, Running, Failed, Cancelled, RolledBack, "UNKNOWN"}
	allowed := map[State][]State{
		Submitted:   {Validating, Failed, Cancelled},
		Validating:  {Cloning, Failed, Cancelled},
		Cloning:     {Building, Failed, Cancelled},
		Building:    {Scanning, Failed, Cancelled},
		Scanning:    {Approved, Failed, Cancelled},
		Approved:    {Deploying, Failed, Cancelled},
		Deploying:   {HealthCheck, Failed, Cancelled},
		HealthCheck: {Running, Failed, Cancelled, RolledBack},
		Running:     {RolledBack},
		Failed:      {RolledBack},
	}
	for _, from := range states {
		for _, to := range states {
			want := false
			for _, target := range allowed[from] {
				want = want || target == to
			}
			if got := CanTransition(from, to); got != want {
				t.Errorf("%s -> %s: got %v, want %v", from, to, got, want)
			}
		}
	}
}
