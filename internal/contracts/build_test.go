package contracts

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func buildTestJob() BuildJob {
	now := time.Now().UTC()
	p := ClonePolicy{Version: 1, Hosts: []string{"github.com"}, Limits: DefaultCloneLimits()}
	c := CloneJob{Version: 1, JobID: "11111111-1111-4111-8111-111111111111", DeploymentID: "22222222-2222-4222-8222-222222222222", LeaseID: "33333333-3333-4333-8333-333333333333", Attempt: 1, Generation: 1, ExpiresAt: now.Add(25 * time.Minute), TemplateDigest: Digest([]byte("template")), PolicyHash: p.Hash(), RepositoryURL: "https://github.com/test/repo", Branch: "main", ConfigPath: "Dockerfile", BuildContext: ".", Policy: p}
	policy := BuildPolicy{EgressPolicyHash: strings.Repeat("a", 64), UploadOrigin: "https://ingest.example.com", Version: 1, BuildSeconds: 1200, ScanSeconds: 300, Limits: DefaultArtifactLimits(), ScannerDigest: Digest([]byte("scanner")), DatabaseDigest: Digest([]byte("db")), DatabaseCreatedAt: now.Add(-time.Hour), DatabaseMaxAgeSeconds: 172800}
	c.Build = &BuildSettings{Policy: policy, Dockerfile: "Dockerfile"}
	return BuildJob{Version: 1, Clone: c, SHA: strings.Repeat("a", 40), ContextID: strings.Repeat("b", 64), Policy: policy, PolicyHash: policy.Hash(), Dockerfile: "Dockerfile", ExpiresAt: c.ExpiresAt}
}
func TestBuildContractStrictness(t *testing.T) {
	j := buildTestJob()
	data, e := BuildInput(j, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	got, e := ReadBuildInput(bytes.NewReader(data), time.Now())
	if e != nil || got.SHA != j.SHA {
		t.Fatal(got, e)
	}
	raw, _ := json.Marshal(j)
	for name, mutate := range map[string]func([]byte) []byte{
		"unknown":   func(b []byte) []byte { return append([]byte(`{"unknown":1,`), b[1:]...) },
		"duplicate": func(b []byte) []byte { return append([]byte(`{"version":1,`), b[1:]...) },
		"case":      func(b []byte) []byte { return bytes.Replace(b, []byte(`"version"`), []byte(`"Version"`), 1) },
		"trailing":  func(b []byte) []byte { return append(b, []byte(`{}`)...) },
		"oversize":  func(b []byte) []byte { return bytes.Repeat([]byte(" "), MaxBuildJobBytes+1) },
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := DecodeBuildJob(bytes.NewReader(mutate(raw)), time.Now()); e == nil {
				t.Fatal("accepted")
			}
		})
	}
	for _, name := range []string{"sha", "context", "deadline", "db-stale", "db-future", "limit", "policy-hash", "path", "exception", "undeclared-build"} {
		t.Run(name, func(t *testing.T) {
			b := j
			switch name {
			case "undeclared-build":
				b.Clone.Build = nil
			case "sha":
				b.SHA = "bad"
			case "context":
				b.ContextID = "bad"
			case "deadline":
				b.ExpiresAt = time.Now().Add(-time.Second)
			case "db-stale":
				b.Policy.DatabaseCreatedAt = time.Now().Add(-72 * time.Hour)
			case "db-future":
				b.Policy.DatabaseCreatedAt = time.Now().Add(time.Hour)
			case "limit":
				b.Policy.Limits.Entries = 100001
			case "policy-hash":
				b.PolicyHash = Digest([]byte("other"))
			case "path":
				b.Dockerfile = "../Dockerfile"
			case "exception":
				b.Policy.Exceptions = []ScanException{{Vulnerability: "CVE-x", Package: "x", Digest: Digest(nil), ExpiresAt: time.Now().Add(-time.Hour)}}
			}
			if b.Validate(time.Now()) == nil {
				t.Fatal("accepted")
			}
		})
	}
}
func TestBuildResultBoundIdentity(t *testing.T) {
	j := buildTestJob()
	r := ArtifactResult{Version: 1, JobID: j.Clone.JobID, DeploymentID: j.Clone.DeploymentID, Attempt: 1, Generation: 1, PolicyHash: j.PolicyHash, ArchiveDigest: Digest([]byte("archive")), ImageDigest: Digest([]byte("manifest")), ScannerDigest: j.Policy.ScannerDigest, DatabaseDigest: j.Policy.DatabaseDigest, ReportDigest: Digest([]byte("report")), SBOMDigest: Digest([]byte("sbom")), Outcome: "admitted"}
	if r.Validate(j) != nil {
		t.Fatal("valid result")
	}
	r.Generation++
	if r.Validate(j) == nil {
		t.Fatal("stale result")
	}
	r.Generation--
	r.ImageDigest = ""
	if r.Validate(j) == nil {
		t.Fatal("missing digest")
	}
	r.Outcome = "denied"
	r.ReportDigest = "sentinel-secret"
	if r.Validate(j) == nil {
		t.Fatal("raw diagnostic accepted")
	}
}

func FuzzBuildJob(f *testing.F) {
	b, _ := json.Marshal(buildTestJob())
	f.Add(b)
	f.Add([]byte(`{"version":1,"version":2}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = DecodeBuildJob(bytes.NewReader(b), time.Now()) })
}
func TestBuildAuthorizationStrict(t *testing.T) {
	j := buildTestJob()
	j.Clone.Build = &BuildSettings{Policy: j.Policy, Dockerfile: j.Dockerfile}
	a := BuildAuthorization{Job: j, ObjectID: strings.Repeat("a", 32), Token: strings.Repeat("b", 64)}
	b, _ := json.Marshal(a)
	if _, e := DecodeBuildAuthorization(bytes.NewReader(b), j.Clone, time.Now()); e != nil {
		t.Fatal(e)
	}
	b = bytes.Replace(b, []byte(`"dockerfile":"Dockerfile"`), []byte(`"dockerfile":"Dockerfile","unknown":1`), 1)
	if _, e := DecodeBuildAuthorization(bytes.NewReader(b), j.Clone, time.Now()); e == nil {
		t.Fatal("unknown nested field")
	}
	a.Job.SHA = "bad"
	if a.Validate(j.Clone, time.Now()) == nil {
		t.Fatal("bad authorization")
	}
}
