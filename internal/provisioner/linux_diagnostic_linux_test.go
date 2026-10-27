package provisioner

import (
	"bytes"
	"testing"
)

func TestLaunchDiagnosticIsBoundedAndDrains(t *testing.T) {
	var d launchDiagnostic
	for _, size := range []int{10, 8192, 32} {
		p := bytes.Repeat([]byte("x"), size)
		n, err := d.Write(p)
		if n != size || err != nil {
			t.Fatalf("write did not drain: %d %v", n, err)
		}
	}
	if d.Len() != 4096 || d.String() != string(bytes.Repeat([]byte("x"), 4096)) {
		t.Fatal("diagnostic prefix not bounded")
	}
}
