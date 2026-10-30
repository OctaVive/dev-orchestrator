package contracts

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func cloneFixture() CloneJob {
	p := ClonePolicy{Version: 1, Hosts: []string{"git.example.com"}, Limits: DefaultCloneLimits()}
	return CloneJob{Version: 1, JobID: "11111111-1111-4111-8111-111111111111", DeploymentID: "22222222-2222-4222-8222-222222222222", LeaseID: "33333333-3333-4333-8333-333333333333", Attempt: 1, Generation: 1, ExpiresAt: time.Now().UTC().Add(5 * time.Minute), TemplateDigest: "sha256:" + strings.Repeat("a", 64), PolicyHash: p.Hash(), RepositoryURL: "https://git.example.com/repo.git", Branch: "main", ConfigPath: "Dockerfile", BuildContext: ".", Policy: p}
}
func TestCloneContractAndImmutableInput(t *testing.T) {
	j := cloneFixture()
	data, e := CloneInput(j, time.Now())
	if e != nil || len(data)%512 != 0 {
		t.Fatal(e)
	}
	got, e := ReadCloneInput(bytes.NewReader(data), time.Now())
	if e != nil || got.JobID != j.JobID {
		t.Fatal(e)
	}
	for _, change := range []func(*CloneJob){func(j *CloneJob) { j.PolicyHash = strings.Repeat("b", 64) }, func(j *CloneJob) { j.LeaseID = "wrong" }, func(j *CloneJob) { j.ExpiresAt = time.Now().Add(-time.Second) }, func(j *CloneJob) { j.RepositoryURL = "https://other.example.com/r" }, func(j *CloneJob) { j.Policy.Limits.TransferBytes = 2 << 30; j.PolicyHash = j.Policy.Hash() }, func(j *CloneJob) { j.Branch = "--upload-pack=evil" }, func(j *CloneJob) { j.ConfigPath = "a/../Dockerfile" }} {
		bad := j
		bad.Policy.Hosts = append([]string(nil), j.Policy.Hosts...)
		change(&bad)
		if bad.Validate(time.Now()) == nil {
			t.Fatal("unsafe clone accepted")
		}
	}
	b, _ := json.Marshal(j)
	for _, bad := range [][]byte{append(b, []byte("{}")...), bytes.Replace(b, []byte(`"version":1`), []byte(`"Version":1`), 1), bytes.Replace(b, []byte(`"version":1`), []byte(`"version":1,"Version":1`), 1), bytes.Replace(b, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1), bytes.Replace(b, []byte(`"version":1`), []byte(`"version":1,"command":"evil"`), 1), bytes.Repeat([]byte{'a'}, MaxCloneJobBytes+1)} {
		if _, e := DecodeCloneJob(bytes.NewReader(bad), time.Now()); e == nil {
			t.Fatal("ambiguous clone JSON")
		}
	}
	for _, bad := range [][]byte{data[:11], append([]byte("NOTMAGIC"), data[8:]...), append(data[:8], 0xff, 0xff, 0xff, 0xff)} {
		if _, e := ReadCloneInput(bytes.NewReader(bad), time.Now()); e == nil {
			t.Fatal("invalid device input")
		}
	}
}
func TestCloneResultBinding(t *testing.T) {
	j := cloneFixture()
	r := NewCloneResult(j)
	r.SHA = strings.Repeat("a", 40)
	r.Outcome = "resolved"
	if r.Validate(j) != nil {
		t.Fatal("valid resolution")
	}
	for _, change := range []func(*CloneResult){func(r *CloneResult) { r.LeaseID = j.JobID }, func(r *CloneResult) { r.Attempt++ }, func(r *CloneResult) { r.ObjectFormat = "sha256" }, func(r *CloneResult) { r.SHA = strings.Repeat("0", 40) }, func(r *CloneResult) { r.Outcome = "success" }, func(r *CloneResult) { r.Bytes = j.Policy.Limits.ContextBytes + 1 }, func(r *CloneResult) { r.Outcome = "raw stderr secret" }} {
		bad := r
		change(&bad)
		if bad.Validate(j) == nil {
			t.Fatal("invalid result")
		}
	}
}
func FuzzCloneInput(f *testing.F) {
	j := cloneFixture()
	b, _ := json.Marshal(j)
	f.Add(b)
	f.Add([]byte(`{"version":1,"version":2}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = DecodeCloneJob(bytes.NewReader(b), time.Now()) })
}
