//go:build linux

package provisioner

import (
	"bytes"
	"context"
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/tests/fixtures/oci"
	"encoding/json"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRealM07RootlessFeasibility(t *testing.T) {
	if os.Getenv("M07_DISPOSABLE_HOST") != "YES-I-AUTHORIZE-BUILD-LAB" {
		t.Skip("M07 isolated lab not enabled")
	}
	b := hostLab(t)
	m := labMachine(t, b, 180*time.Second)
	labCreate(t, b, m)
	t.Cleanup(func() {
		f, e := os.Open(filepath.Join(b.c.Root, m.Lease.JobID+".raw"))
		if e == nil {
			defer f.Close()
			data := make([]byte, 49152)
			_, _ = f.ReadAt(data, 20971390*512)
			t.Log(strings.TrimRight(string(data), "\x00"))
		}
	})
	marker := matrixMarker(t, b, m, "M07-FEASIBILITY", 150*time.Second)
	if !strings.Contains(marker, "build=0 workers=0") {
		t.Fatal(marker)
	}
	matrixInspect(t, b, m)
}

func TestRealM07Ingest(t *testing.T) {
	if os.Getenv("M07_DISPOSABLE_HOST") != "YES-I-AUTHORIZE-BUILD-LAB" {
		t.Skip("M07 isolated lab not enabled")
	}
	b := hostLab(t)
	for _, name := range []string{"clean", "vulnerable", "malformed"} {
		t.Run(name, func(t *testing.T) {
			j := m07Job(t)
			data := ocifixture.Image(name == "vulnerable")
			if name == "malformed" {
				data[0] = '!'
			}
			id := strings.ReplaceAll(matrixID(t), "-", "")
			p := filepath.Join(b.c.ArtifactRoot, id)
			if e := os.WriteFile(p, data, 0600); e != nil {
				t.Fatal(e)
			}
			m := labMachine(t, b, 240*time.Second, func(m *Machine) {
				m.Lease.DeploymentID = j.Clone.DeploymentID
				m.Ingest = &contracts.IngestJob{Build: j, ObjectID: id, Bytes: int64(len(data)), ArchiveDigest: contracts.Digest(data)}
			})
			labCreate(t, b, m)
			t.Cleanup(func() {
				f, e := os.Open(filepath.Join(b.c.Root, m.Lease.JobID+".raw"))
				if e == nil {
					defer f.Close()
					log := make([]byte, 49152)
					_, _ = f.ReadAt(log, 20971390*512)
					t.Log(strings.TrimRight(string(log), "\x00"))
				}
			})

			deadline := time.Now().Add(200 * time.Second)
			var result contracts.ArtifactResult
			done := false
			for time.Now().Before(deadline) {
				var e error
				result, done, e = b.IngestResult(context.Background(), m)
				if e != nil {
					t.Fatal(e)
				}
				if done {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if !done {
				t.Fatal("ingest result timeout")
			}
			t.Logf("normalized result: %+v", result)
			if (name == "clean") != (result.Outcome == "admitted") {
				t.Fatal("wrong decision", result)
			}
			marker := matrixMarker(t, b, m, "M07-INGEST", 10*time.Second)
			if !strings.Contains(marker, "tests=0 runner=0") {
				t.Fatal(marker)
			}
			f, e := os.Open(filepath.Join(b.c.Root, m.Lease.JobID+".raw"))
			if e != nil {
				t.Fatal(e)
			}
			defer f.Close()
			log := make([]byte, 49152)
			_, _ = f.ReadAt(log, 20971390*512)
			text := strings.TrimRight(string(log), "\x00")
			t.Log(text)
			if strings.Contains(text, "--- FAIL:") || strings.Contains(text, "--- SKIP:") || !strings.Contains(text, "--- PASS: TestGuestOCIValidation") || !strings.Contains(text, "--- PASS: TestGuestRealTrivy") {
				t.Fatal("guest corpus incomplete")
			}
		})
	}
}
func m07Job(t *testing.T) contracts.BuildJob {
	t.Helper()
	lock, e := os.ReadFile(os.Getenv("M07_TOOLS_LOCK"))
	if e != nil {
		t.Fatal(e)
	}
	var pins struct {
		DB struct {
			SHA      string `json:"sha256"`
			Metadata struct {
				UpdatedAt time.Time `json:"UpdatedAt"`
			} `json:"metadata"`
		} `json:"vulnerability_database"`
	}
	if json.Unmarshal(lock, &pins) != nil {
		t.Fatal("pins")
	}
	tool, e := os.ReadFile(os.Getenv("M07_TRIVY"))
	if e != nil {
		t.Fatal(e)
	}
	clone := cloneTestJob()
	clone.ExpiresAt = time.Now().Add(25 * time.Minute)
	p := contracts.BuildPolicy{EgressPolicyHash: strings.Repeat("a", 64), UploadOrigin: "https://ingest.example.com", Version: 1, BuildSeconds: 1200, ScanSeconds: 300, Limits: contracts.DefaultArtifactLimits(), ScannerDigest: contracts.Digest(tool), DatabaseDigest: "sha256:" + pins.DB.SHA, DatabaseCreatedAt: pins.DB.Metadata.UpdatedAt, DatabaseMaxAgeSeconds: 172800}
	clone.Build = &contracts.BuildSettings{Policy: p, Dockerfile: "Dockerfile"}
	return contracts.BuildJob{Version: 1, Clone: clone, SHA: strings.Repeat("b", 40), ContextID: strings.Repeat("c", 64), Policy: p, PolicyHash: p.Hash(), Dockerfile: "Dockerfile", ExpiresAt: clone.ExpiresAt}
}

func TestBuildSerialFrameFencing(t *testing.T) {
	j := cloneTestJob()
	p := contracts.BuildPolicy{EgressPolicyHash: strings.Repeat("a", 64), UploadOrigin: "https://ingest.example.com", Version: 1, BuildSeconds: 20, ScanSeconds: 20, Limits: contracts.DefaultArtifactLimits(), ScannerDigest: contracts.Digest(nil), DatabaseDigest: contracts.Digest(nil), DatabaseCreatedAt: time.Now().Add(-time.Hour), DatabaseMaxAgeSeconds: 172800}
	j.Build = &contracts.BuildSettings{Policy: p, Dockerfile: "Dockerfile"}
	resolved := contracts.NewCloneResult(j)
	resolved.Outcome = "resolved"
	resolved.SHA = strings.Repeat("b", 40)
	success := resolved
	success.Outcome = "success"
	success.ContextID = strings.Repeat("c", 64)
	success.Entries = 1
	first, _ := json.Marshal(resolved)
	second, _ := json.Marshal(success)
	prefix := append(append([]byte("M06 "+string(first)+"\n"), []byte("M06 "+string(second)+"\n")...), []byte{}...)
	terminal, _ := json.Marshal(contracts.BuildResult{JobID: j.JobID, PolicyHash: p.Hash(), Outcome: "exported"})
	valid := append(append([]byte(nil), prefix...), []byte("M07 "+string(terminal)+"\n")...)
	if r, e := parseCloneFrames(valid, j); e != nil || len(r) != 2 {
		t.Fatal(r, e)
	}
	for _, data := range [][]byte{append(valid, []byte("garbage\n")...), bytes.Replace(valid, []byte(`"exported"`), []byte(`"unknown"`), 1), bytes.Replace(valid, []byte(`"outcome":"exported"`), []byte(`"outcome":"exported","token":"secret"`), 1), append([]byte("M07 "+string(terminal)+"\n"), prefix...)} {
		if _, e := parseCloneFrames(data, j); e == nil {
			t.Fatal("invalid build frame accepted")
		}
	}
}

func TestBuildBoottimeTimerRearm(t *testing.T) {
	timer, e := unix.TimerfdCreate(unix.CLOCK_BOOTTIME, unix.TFD_CLOEXEC)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(timer)
	now, e := bootNow()
	if e != nil {
		t.Fatal(e)
	}
	if e = unix.TimerfdSettime(timer, unix.TFD_TIMER_ABSTIME, &unix.ItimerSpec{Value: unix.NsecToTimespec(now + int64(time.Hour))}, nil); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { var data [8]byte; _, e := unix.Read(timer, data[:]); done <- e }()
	time.Sleep(10 * time.Millisecond)
	now, e = bootNow()
	if e != nil {
		t.Fatal(e)
	}
	if e = unix.TimerfdSettime(timer, unix.TFD_TIMER_ABSTIME, &unix.ItimerSpec{Value: unix.NsecToTimespec(now + int64(20*time.Millisecond))}, nil); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("rearmed timer did not expire")
	}
}
