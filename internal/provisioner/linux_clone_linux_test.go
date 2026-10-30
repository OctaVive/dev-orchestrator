//go:build linux

package provisioner

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"dev-orchestrator/internal/contracts"
	"golang.org/x/sys/unix"
)

func cloneTestJob() contracts.CloneJob {
	p := contracts.ClonePolicy{Version: 1, Hosts: []string{"ok.m06.example"}, Limits: contracts.DefaultCloneLimits()}
	return contracts.CloneJob{Version: 1, JobID: "11111111-1111-4111-8111-111111111111", DeploymentID: "22222222-2222-4222-8222-222222222222", LeaseID: "33333333-3333-4333-8333-333333333333", Attempt: 1, Generation: 1, ExpiresAt: time.Now().UTC().Add(5 * time.Minute), TemplateDigest: "sha256:" + strings.Repeat("a", 64), PolicyHash: p.Hash(), RepositoryURL: "https://ok.m06.example/good.git", Branch: "main", ConfigPath: "Dockerfile", BuildContext: ".", Policy: p}
}
func TestCloneDeviceSealsFramingAndBounds(t *testing.T) {
	j := cloneTestJob()
	f, e := cloneInputFD(j)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	seals, e := unix.FcntlInt(f.Fd(), unix.F_GET_SEALS, 0)
	if e != nil || seals&unix.F_SEAL_WRITE == 0 {
		t.Fatal("unsealed input", e)
	}
	if _, e = f.Write([]byte("overwrite")); e == nil {
		t.Fatal("writable job")
	}
	got, e := contracts.ReadCloneInput(f, time.Now())
	if e != nil || got.JobID != j.JobID {
		t.Fatal(got, e)
	}
	r := contracts.NewCloneResult(j)
	r.Outcome = "resolved"
	r.SHA = strings.Repeat("b", 40)
	data, _ := json.Marshal(r)
	frame := append([]byte("M06 "), append(data, '\n')...)
	r.Outcome = "success"
	r.ContextID = strings.Repeat("c", 64)
	r.Entries = 1
	final, _ := json.Marshal(r)
	both := append(append([]byte(nil), frame...), append([]byte("M06 "), append(final, '\n')...)...)
	if frames, e := parseCloneFrames(both, j); e != nil || len(frames) != 2 {
		t.Fatal(frames, e)
	}
	for _, bad := range [][]byte{append(both, frame...), append([]byte("garbage\n"), frame...), append([]byte("M06 "), append(final, '\n')...), bytes.Replace(frame, []byte(j.LeaseID), []byte(j.JobID), 1)} {
		if _, e := parseCloneFrames(bad, j); e == nil {
			t.Fatal("forged/invalid serial accepted")
		}
	}
	s := &cloneSerial{}
	if _, e = s.Write(bytes.Repeat([]byte{'x'}, cloneSerialLimit+1)); e == nil || !s.overflow || len(s.data) != 0 {
		t.Fatal("serial unbounded")
	}
	if frames, e := parseCloneFrames(frame[:len(frame)-1], j); e != nil || len(frames) != 0 {
		t.Fatal("partial frame was final")
	}
	state := hostMachine{CloneVersion: 99}
	if validateNetworkState(state) == nil {
		t.Fatal("unknown clone manifest")
	}
}

func newCloneLabMachine(t *testing.T, b *linuxBackend, scenario string) Machine {
	t.Helper()
	j := cloneTestJob()
	var id [16]byte
	_, _ = rand.Read(id[:])
	id[6] = id[6]&15 | 64
	id[8] = id[8]&63 | 128
	j.JobID = fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])
	j.LeaseID = j.JobID
	j.TemplateDigest = b.c.Digest
	j.RepositoryURL = "https://ok.m06.example/" + scenario + ".git"
	j.ExpiresAt = time.Now().UTC().Add(90 * time.Second)
	if scenario == "expiry-controller-loss" {
		j.ExpiresAt = time.Now().UTC().Add(35 * time.Second)
		j.RepositoryURL = "https://ok.m06.example/stall-fetch.git"
	}
	if scenario == "nested" || scenario == "context-escape" || scenario == "context-return" || scenario == "deep-tree" {
		j.ConfigPath = "src/Dockerfile"
		j.BuildContext = "src"
	}
	if scenario == "deep-tree" {
		j.Policy.Limits.Depth = 1
	}
	if scenario == "long-path" {
		j.Policy.Limits.PathBytes = 8
	}
	if scenario == "object-count" {
		j.Policy.Limits.Objects = 1
	}
	if scenario == "expanded-limit" {
		j.Policy.Limits.ExpandedBytes = 16
	}
	if scenario == "timeout" {
		j.Policy.Limits.Seconds = 2
	}
	if scenario == "object-limit" {
		j.Policy.Limits.ObjectBytes = 64
	}
	if scenario == "context-limit" {
		j.Policy.Limits.ContextBytes = 8
	}
	if scenario == "entry-limit" {
		j.Policy.Limits.Entries = 1
	}
	if scenario == "ref-limit" {
		j.Policy.Limits.Refs = 1
	}
	if scenario == "transfer-limit" {
		j.Policy.Limits.TransferBytes = 1024
	}
	if scenario == "adv-limit" {
		j.Policy.Limits.AdvertisementBytes = 1024
	}
	for _, name := range []string{"rebind", "private", "metadata", "infra", "mixed", "mapped", "v6", "badcert", "dnsfail"} {
		if scenario == name {
			j.Policy.Hosts = []string{name + ".m06.example"}
			j.RepositoryURL = "https://" + name + ".m06.example/good.git"
		}
	}
	j.PolicyHash = j.Policy.Hash()
	var proof [32]byte
	_, _ = rand.Read(proof[:])
	m := Machine{Lease: Lease{JobID: j.JobID, CommandID: j.LeaseID, DeploymentID: j.DeploymentID, ProfileID: "build-small-v1", Template: Template{b.c.TemplateID, b.c.Digest}, ExpiresAt: j.ExpiresAt, CreatedAt: time.Now().UTC()}, Budget: SmallBudget(), OwnershipProof: hex.EncodeToString(proof[:]), Clone: &j}
	t.Logf("clone job %s scenario %s", j.JobID, scenario)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		r, e := b.Cleanup(ctx, m)
		if e != nil || !r.VMAbsent || !r.ArtifactsAbsent || !r.StartFenced {
			t.Errorf("clone cleanup: %+v %v", r, e)
		}
	})
	return m
}

func TestRealCloneCorpus(t *testing.T) {
	if os.Getenv("M06_DISPOSABLE_HOST") != "YES-I-AUTHORIZE-CLONE-LAB" {
		t.Skip("requires disposable M06 KVM lab")
	}
	b := hostLab(t)
	if !b.c.CloneEnabled {
		t.Fatal("clone runner disabled")
	}
	if dir := os.Getenv("M06_CAPTURE_DIR"); dir != "" {
		hostCapture := startLabCapture(t, nil, filepath.Join(dir, "clone-host.pcap"), true)
		defer func() {
			hostCapture.stop()
			if hostCapture.err != nil || hostCapture.summary["capture_drops"] != 0 || hostCapture.summary["guest_frames_on_host"] != 0 || hostCapture.summary["protected_destination_frames"] != 0 {
				t.Error("host boundary capture failed", hostCapture.err, hostCapture.summary)
			}
			data, _ := json.Marshal(hostCapture.summary)
			if os.WriteFile(filepath.Join(dir, "clone-host-capture.json"), data, 0600) != nil {
				t.Error("host capture evidence write")
			}
		}()
	}
	scenarios := []string{"good", "executable", "symlink", "moving", "mismatch", "submodule", "modules", "attributes", "lfs", "escape", "cycle", "collision", "metadata-path", "malformed", "sha256", "redirect", "redirect-same", "timeout", "object-limit", "context-limit", "entry-limit", "ref-limit", "transfer-limit", "adv-limit", "corrupt", "rebind", "private", "metadata", "infra", "mixed", "mapped", "v6", "badcert", "dnsfail", "nested", "context-escape", "config-symlink", "deep-tree", "long-path", "object-count", "expanded-limit", "huge-object", "huge-ref-list", "log-flood", "redirect-301", "redirect-303", "redirect-307", "redirect-308", "directory-link", "directory-cycle", "context-return"}
	if only := os.Getenv("M06_CASES"); only != "" {
		scenarios = strings.Split(only, ",")
	}
	for _, scenario := range scenarios {
		t.Run(scenario, func(t *testing.T) {
			m := newCloneLabMachine(t, b, scenario)
			var capture *labCapture
			if dir := os.Getenv("M06_CAPTURE_DIR"); dir != "" {
				b.networkStage = func(stage string) error {
					if stage == "enabled" {
						s, e := b.read(m.Lease.JobID)
						if e != nil {
							return e
						}
						capture = startLabCapture(t, s.Network, filepath.Join(dir, m.Lease.JobID+".pcap"), false)
					}
					return nil
				}
				defer func() {
					b.networkStage = nil
					if capture != nil {
						capture.stop()
						data, _ := json.Marshal(capture.summary)
						if os.WriteFile(filepath.Join(dir, m.Lease.JobID+".capture.json"), data, 0600) != nil {
							t.Error("capture summary write")
						}
						if capture.err != nil || capture.summary["capture_drops"] != 0 {
							t.Error("capture incomplete")
						}
					}
				}()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			e := b.Create(ctx, m)
			cancel()
			if e != nil {
				t.Fatal("create", e)
			}
			deadline := time.Now().Add(50 * time.Second)
			var frames []contracts.CloneResult
			for time.Now().Before(deadline) {
				frames, e = b.CloneResults(context.Background(), m)
				if e != nil {
					t.Fatal(e)
				}
				if len(frames) > 0 && frames[len(frames)-1].Outcome != "resolved" {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if len(frames) == 0 || frames[len(frames)-1].Outcome == "resolved" {
				f, _ := os.Open(filepath.Join(b.c.Root, m.Lease.JobID+".raw"))
				if f != nil {
					var marker [512]byte
					_, _ = f.ReadAt(marker[:], (int64(SmallBudget().VirtualDiskMiB)<<20)-512)
					t.Logf("fixed boot marker %q", bytes.TrimRight(marker[:], "\x00"))
					_ = f.Close()
				}
				t.Fatal("no final result")
			}
			final := frames[len(frames)-1]
			t.Logf("result outcome=%s sha=%s entries=%d bytes=%d", final.Outcome, final.SHA, final.Entries, final.Bytes)
			wantSuccess := scenario == "good" || scenario == "executable" || scenario == "symlink" || scenario == "v6" || scenario == "nested" || scenario == "directory-link"
			if wantSuccess != (final.Outcome == "success") {
				t.Fatalf("unexpected result %+v", final)
			}
			if scenario == "timeout" && final.Outcome != "timeout" {
				t.Fatal("deadline not enforced")
			}
			if wantSuccess && len(frames) != 2 {
				t.Fatal("resolution missing")
			}
			markerFile, e := os.Open(filepath.Join(b.c.Root, m.Lease.JobID+".raw"))
			if e != nil {
				t.Fatal(e)
			}
			var bootMarker [512]byte
			markerDeadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(markerDeadline) {
				_, e = markerFile.ReadAt(bootMarker[:], (int64(SmallBudget().VirtualDiskMiB)<<20)-512)
				if e != nil {
					t.Fatal(e)
				}
				if bytes.Contains(bootMarker[:], []byte("CLONE-EXIT")) {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			_ = markerFile.Close()
			if !bytes.Contains(bootMarker[:], []byte("helper=absent filter=absent hook=absent")) {
				t.Fatalf("guest execution sentinel failure %q", bytes.TrimRight(bootMarker[:], "\x00"))
			}
			if wantSuccess && !bytes.Contains(bootMarker[:], []byte("context_check=PASS")) {
				t.Fatalf("guest context verification failed %q", bytes.TrimRight(bootMarker[:], "\x00"))
			}
			if scenario == "good" && (final.Entries != 2 || final.Bytes != 35) {
				t.Fatal("wrong tracked context statistics", final.Entries, final.Bytes)
			}
			if path := os.Getenv("M06_EXPECTED_SHAS"); path != "" && final.SHA != "" {
				data, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				var expected map[string]string
				if json.Unmarshal(data, &expected) != nil {
					t.Fatal("bad expected SHA map")
				}
				key := scenario
				if scenario == "v6" || scenario == "rebind" {
					key = "good"
				}
				if want, ok := expected[key]; ok && final.SHA != want {
					t.Fatal("wrong immutable revision", final.SHA, want)
				}
			}
			if dir := os.Getenv("M06_CAPTURE_DIR"); dir != "" {
				data, _ := json.Marshal(frames)
				if os.WriteFile(filepath.Join(dir, scenario+".json"), data, 0600) != nil {
					t.Fatal("write evidence")
				}
			}
		})
	}
}

func TestRealCloneLifecycle(t *testing.T) {
	if os.Getenv("M06_DISPOSABLE_HOST") != "YES-I-AUTHORIZE-CLONE-LAB" {
		t.Skip("requires disposable M06 KVM lab")
	}
	for _, scenario := range []string{"cancel-resolve", "cancel-fetch", "expiry-controller-loss", "worker-loss", "cancel-export"} {
		t.Run(scenario, func(t *testing.T) {
			b := hostLab(t)
			source := "timeout"
			if scenario == "cancel-fetch" || scenario == "expiry-controller-loss" || scenario == "worker-loss" {
				source = "stall-fetch"
			}
			if scenario == "cancel-export" {
				source = "good"
			}
			machineScenario := source
			if scenario == "expiry-controller-loss" {
				machineScenario = scenario
			}
			m := newCloneLabMachine(t, b, machineScenario)
			m.Clone.Policy.Limits.Seconds = 300
			m.Clone.PolicyHash = m.Clone.Policy.Hash()
			started := time.Now()

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			e := b.Create(ctx, m)
			cancel()
			if e != nil {
				t.Fatal(e)
			}
			if source == "timeout" {
				waitCloneFixtureArrival(t, "/timeout.git/info/refs", "GET", started)
			}
			if source != "timeout" {
				deadline := time.Now().Add(25 * time.Second)
				found := false
				for time.Now().Before(deadline) {
					frames, e := b.CloneResults(context.Background(), m)
					if e != nil {
						t.Fatal(e)
					}
					if len(frames) > 0 && (source != "good" || frames[len(frames)-1].Outcome == "success") {
						found = true
						break
					}
					time.Sleep(50 * time.Millisecond)
				}
				if !found {
					t.Fatal("did not reach controlled cancellation phase")
				}
				if source == "stall-fetch" {
					waitCloneFixtureArrival(t, "/stall-fetch.git/git-upload-pack", "POST", started)
				}
			}
			if scenario == "expiry-controller-loss" {
				// Freeze the guest and broker supervisors. PID-1 expiry must still
				// terminate the exact owned guest/broker without this controller.
				for _, unit := range []string{unitName(m.Lease.JobID), brokerUnit(m.Lease.JobID)} {
					out, e := hostCommand(context.Background(), "/usr/bin/systemctl", "show", unit, "--property=MainPID", "--value")
					if e != nil {
						t.Fatal(e)
					}
					var pid int
					if _, e = fmt.Sscanf(strings.TrimSpace(out), "%d", &pid); e != nil || pid < 2 {
						t.Fatal("missing supervisor", e)
					}
					if e = syscall.Kill(pid, syscall.SIGSTOP); e != nil {
						t.Fatal(e)
					}
				}
				deadline := m.Lease.ExpiresAt.Add(8 * time.Second)
				for time.Now().Before(deadline) {
					_, active, e := b.unit(context.Background(), m)
					if e != nil {
						t.Fatal(e)
					}
					if !active {
						break
					}
					time.Sleep(100 * time.Millisecond)
				}
				if _, active, e := b.unit(context.Background(), m); e != nil || active {
					t.Fatal("independent expiry failed", e)
				}
			} else if scenario == "worker-loss" {
				if _, e = hostCommand(context.Background(), "/usr/bin/systemctl", "kill", "--signal=SIGKILL", "--kill-whom=all", unitName(m.Lease.JobID)); e != nil {
					t.Fatal(e)
				}
			}
			r, e := b.Cleanup(context.Background(), m)
			if e != nil || !r.VMAbsent || !r.ArtifactsAbsent || !r.StartFenced {
				t.Fatal("cleanup unconfirmed", r, e)
			}
			if _, e = b.CloneResults(context.Background(), m); e == nil {
				t.Fatal("late result accepted")
			}
			if e = b.Create(context.Background(), m); e == nil {
				t.Fatal("delayed start accepted")
			}
		})
	}
}

func waitCloneFixtureArrival(t *testing.T, prefix, method string, since time.Time) {
	t.Helper()
	log := os.Getenv("M06_CANARY_LOG")
	if log == "" {
		t.Fatal("controlled fixture log required")
	}
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		data, e := os.ReadFile(log)
		if e == nil {
			for _, line := range bytes.Split(data, []byte{'\n'}) {
				var event struct {
					Kind   string  `json:"kind"`
					Time   float64 `json:"time"`
					Path   string  `json:"path"`
					Method string  `json:"method"`
				}
				if json.Unmarshal(line, &event) == nil && event.Kind == "http" && event.Method == method && strings.HasPrefix(event.Path, prefix) && event.Time >= float64(since.UnixNano())/1e9 {
					return
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("guest did not reach controlled network phase")
}
