package provisioner

import (
	"bytes"
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	// io.Copy must not discover a promoted bytes.Buffer.ReadFrom and bypass
	// Write's limit, as it would with an embedded bytes.Buffer.
	var streamed launchDiagnostic
	if n, e := io.Copy(&streamed, io.LimitReader(strings.NewReader(strings.Repeat("y", 128<<10)), 128<<10)); e != nil || n != 128<<10 || streamed.Len() != 4096 {
		t.Fatal("streamed diagnostic cap", n, e, streamed.Len())
	}
	var output limitedOutput
	if n, e := io.Copy(&output, io.LimitReader(strings.NewReader(strings.Repeat("z", 128<<10)), 128<<10)); e != nil || n != 128<<10 || output.Len() != 32768 {
		t.Fatal("streamed host output cap", n, e, output.Len())
	}
}

func TestGuestCommandInheritedDescriptors(t *testing.T) {
	if os.Getenv("M04_FD_CHILD") == "1" {
		var first unix.Stat_t
		for fd, mode := range map[int]int{3: unix.O_RDWR, 4: unix.O_RDONLY} {
			flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
			if err != nil || flags&unix.O_ACCMODE != mode {
				t.Fatalf("fd %d flags=%d: %v", fd, flags, err)
			}
			var st unix.Stat_t
			if err := unix.Fstat(fd, &st); err != nil {
				t.Fatal(err)
			}
			if first.Ino != 0 && (first.Ino != st.Ino || first.Dev != st.Dev) {
				t.Fatal("inherited descriptors differ in inode/device")
			}
			first = st
		}
		return
	}
	p := filepath.Join(t.TempDir(), "disk.raw")
	rw, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Close()
	ro, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	q := guestCommand(LinuxConfig{QEMU: self, UID: uint32(os.Getuid()), GID: uint32(os.Getgid()), KVMGID: 12345}, rw, ro)
	if q.SysProcAttr.Credential.Groups[0] != 12345 {
		t.Fatal("configured KVM group lost")
	}
	// Normal-user subprocess checks inheritance; credential dropping requires
	// the separate real-host tests. Keep production ExtraFiles unchanged.
	q.SysProcAttr.Credential = nil
	q.Args = []string{self, "-test.run=^TestGuestCommandInheritedDescriptors$"}
	q.Env = append(q.Env, "M04_FD_CHILD=1")
	if out, err := q.CombinedOutput(); err != nil {
		t.Fatalf("inherited descriptor check: %v: %s", err, out)
	}
}

func TestWaitGuestReady(t *testing.T) {
	for _, tc := range []struct {
		name          string
		ready, active bool
		probeErr      error
		want          error
	}{
		{"running", true, true, nil, nil},
		{"exited", false, false, nil, ErrUnavailable},
		{"stale marker", true, false, nil, ErrUnavailable},
		{"foreign unit", false, true, ErrConflict, ErrConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := waitGuestReady(ctx, func() (bool, error) { return tc.ready, nil }, func() (bool, error) { return tc.active, tc.probeErr }, "test.service")
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if tc.want == ErrUnavailable && !strings.Contains(err.Error(), "journalctl -b -u test.service") {
				t.Fatal("missing exact journal diagnostic", err)
			}
		})
	}
	t.Run("delayed start", func(t *testing.T) {
		calls := 0
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		err := waitGuestReady(ctx, func() (bool, error) { calls++; return calls > 1, nil }, func() (bool, error) { return true, nil }, "test.service")
		if err != nil || calls < 2 {
			t.Fatal("did not wait for activating supervisor", err)
		}
	})
	t.Run("cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		err := waitGuestReady(ctx, func() (bool, error) { cancel(); return false, nil }, func() (bool, error) { return true, nil }, "test.service")
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
}

func TestGuestExitRetainsDiagnostic(t *testing.T) {
	for _, cause := range []error{nil, os.ErrPermission} {
		var diagnostic launchDiagnostic
		_, _ = diagnostic.Write([]byte("block initialization failed"))
		err := guestExitError(cause, &diagnostic)
		want := cause
		if want == nil {
			want = ErrUnavailable
		}
		if !errors.Is(err, want) || !strings.Contains(err.Error(), diagnostic.String()) {
			t.Fatalf("lost exit cause or diagnostic: %v", err)
		}
	}
}
