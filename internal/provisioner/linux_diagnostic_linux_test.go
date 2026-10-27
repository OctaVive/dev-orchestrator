package provisioner

import (
	"bytes"
	"strings"
	"testing"
)

func TestQEMUFDSetIncludesBothAccessModes(t *testing.T) {
	args := strings.Join(qemuArgs(), " ")
	for _, required := range []string{"-add-fd fd=3,set=1", "-add-fd fd=4,set=1", "file=/dev/fdset/1,format=raw", "accel=kvm", "-nic none", "throttling.iops-total=1000"} {
		if !strings.Contains(args, required) {
			t.Fatalf("missing fixed QEMU argument %q", required)
		}
	}
}

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
