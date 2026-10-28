package main

import (
	"testing"
)

func TestStartupFailsClosedWithoutOperatorAssignment(t *testing.T) {
	for _, args := range [][]string{nil, {"-unknown", "secret-fixture"}, {"unexpected"}, {"-guest", "192.0.2.2", "-listener-fd", "4"}, {"-guest", "192.0.2.2", "-listen", "0.0.0.0:8443"}, {"-guest", "::1"}} {
		if e := run(args); e == nil || e.Error() != "egress denied" {
			t.Fatalf("startup did not fail generically: %v", e)
		}
	}
}
