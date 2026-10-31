package runtimeisolation

import (
	"os"
	"testing"

	"dev-orchestrator/internal/runtimeagent"
)

func TestMappingBoundsAndRootDenial(t *testing.T) {
	good := []byte("0 1000 1\n1 100000 65536\n")
	maps, err := ParseMappings(good)
	if err != nil || len(maps) != 2 {
		t.Fatal("valid inherited map", err)
	}
	if n, err := MappedID(good, 1000); err != nil || n != 100999 {
		t.Fatal("nonroot mapping", n, err)
	}
	for _, raw := range []string{"", "0 0 65536", "0 1000 1", "0 1000 2\n1 100000 65536", "0 1000 65536\n65536 1001 2", "0 4294967295 2", "0 1000 -1", "0 1000 65536 trailing"} {
		if _, err := ParseMappings([]byte(raw)); err == nil {
			t.Fatal("unsafe mapping", raw)
		}
	}
	if _, err := MappedID(good, 999999); err == nil {
		t.Fatal("unmapped uid")
	}
}
func TestUnenrolledRuntimeDenials(t *testing.T) {
	if _, err := ReadEnrollment("../outside"); err == nil {
		t.Fatal("path selected")
	}
	if VerifyInherited(Enrollment{}) == nil {
		t.Fatal("unenrolled inherited namespace")
	}
	if _, err := VerifyProcess(Enrollment{}, os.Getpid(), ProcessLimits{}); err == nil {
		t.Fatal("unowned process")
	}
	if _, err := EncodeEnrollment(Enrollment{}); err != runtimeagent.ErrDenied {
		t.Fatal("invalid enrollment serialized")
	}
}

func TestMeasuredTmpfsSizes(t *testing.T) {
	for raw, want := range map[string]int64{"rw,size=8192k": 8 << 20, "rw,size=8388608": 8 << 20, "size=64m,nr_inodes=100": 64 << 20} {
		n, err := TmpfsSize(raw)
		if err != nil || n != want {
			t.Fatal(raw, n, err)
		}
	}
	for _, raw := range []string{"rw", "size=0", "size=-1", "size=unlimited", "size=50%", "size=1g,size=2g", "size=999999999999999999999g"} {
		if _, err := TmpfsSize(raw); err == nil {
			t.Fatal("unbounded tmpfs", raw)
		}
	}
}
