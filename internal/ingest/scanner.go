package ingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"dev-orchestrator/internal/contracts"
)

// Scan invokes only the pinned guest template tool, with no inherited proxy,
// credentials, config or ignore files. It never executes the image.
func Scan(parent context.Context, _ string, scratch string, j contracts.BuildJob, v Verified) (contracts.ArtifactResult, error) {
	r := contracts.ArtifactResult{Version: 1, JobID: j.Clone.JobID, DeploymentID: j.Clone.DeploymentID, Attempt: j.Clone.Attempt, Generation: j.Clone.Generation, PolicyHash: j.PolicyHash, Outcome: "denied"}
	if j.Validate(time.Now()) != nil || !contracts.ValidDigest(v.ImageDigest) || !contracts.ValidDigest(v.ArchiveDigest) {
		return r, ErrDenied
	}
	tool, e := os.ReadFile("/usr/bin/trivy")
	if e != nil || contracts.Digest(tool) != j.Policy.ScannerDigest {
		return r, ErrDenied
	}
	metadata, e := os.Open("/scan-cache/db/metadata.json")
	if e != nil {
		return r, ErrDenied
	}
	metadataBytes, e := io.ReadAll(io.LimitReader(metadata, 4097))
	metadata.Close()
	if e != nil || len(metadataBytes) > 4096 || validateReportJSON(metadataBytes) != nil {
		return r, ErrDenied
	}
	var database struct {
		Version   int       `json:"Version"`
		UpdatedAt time.Time `json:"UpdatedAt"`
	}
	if json.Unmarshal(metadataBytes, &database) != nil || database.Version != 2 || !database.UpdatedAt.Equal(j.Policy.DatabaseCreatedAt) {
		return r, ErrDenied
	}
	db, e := os.Open("/scan-cache/db/trivy.db")
	if e != nil {
		return r, ErrDenied
	}
	h, e := digestReader(db)
	db.Close()
	if e != nil || h != j.Policy.DatabaseDigest {
		return r, ErrDenied
	}
	deadline := time.Now().Add(time.Duration(j.Policy.ScanSeconds) * time.Second)
	if j.ExpiresAt.Before(deadline) {
		deadline = j.ExpiresAt
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	dir, e := os.MkdirTemp(scratch, "scan-")
	if e != nil {
		return r, e
	}
	defer os.RemoveAll(dir)
	// DB is read-only template content; cache analysis data goes to private scratch.
	if e = os.MkdirAll(filepath.Join(dir, "cache"), 0700); e != nil {
		return r, e
	}
	if e = os.Symlink("/scan-cache/db", filepath.Join(dir, "cache", "db")); e != nil {
		return r, e
	}
	report, e := runTool(ctx, dir, "json", v.LayoutPath)
	if e != nil {
		return r, e
	}
	high, critical, e := evaluate(report, j.Policy, v.ImageDigest, time.Now())
	if e != nil {
		return r, e
	}
	sbom, e := runTool(ctx, dir, "cyclonedx", v.LayoutPath)
	if e != nil {
		return r, e
	}
	var document struct {
		BOMFormat string `json:"bomFormat"`
	}
	if json.Unmarshal(sbom, &document) != nil || document.BOMFormat != "CycloneDX" {
		return r, ErrDenied
	}
	r.ArchiveDigest = v.ArchiveDigest
	r.ImageDigest = v.ImageDigest
	r.ScannerDigest = j.Policy.ScannerDigest
	r.DatabaseDigest = j.Policy.DatabaseDigest
	r.ReportDigest = contracts.Digest(report)
	r.SBOMDigest = contracts.Digest(sbom)
	r.High = high
	r.Critical = critical
	r.Outcome = "admitted"
	return r, nil
}

// Limited output is shared by the process copy goroutines and kills the whole
// process group on overflow; embedding bytes.Buffer would bypass Write caps.
type toolOutput struct {
	mu     sync.Mutex
	b      bytes.Buffer
	limit  int
	cancel context.CancelFunc
	over   bool
}

func (o *toolOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(p) > o.limit-o.b.Len() {
		o.over = true
		o.cancel()
		return 0, ErrLimit
	}
	return o.b.Write(p)
}
func runTool(parent context.Context, dir, format, archive string) ([]byte, error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/trivy", "image", "--input", archive, "--cache-dir", filepath.Join(dir, "cache"), "--skip-db-update", "--skip-java-db-update", "--offline-scan", "--scanners", "vuln", "--list-all-pkgs", "--format", format, "--quiet", "--ignorefile", "/dev/null", "--config", "/dev/null", "--timeout", "5m")
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "TMPDIR=" + dir, "LANG=C", "TRIVY_CHECKS_BUNDLE_REPOSITORY="}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	cmd.WaitDelay = time.Second
	out := &toolOutput{limit: 16 << 20, cancel: cancel}
	errout := &toolOutput{limit: 64 << 10, cancel: cancel}
	cmd.Stdout = out
	cmd.Stderr = errout
	if e := cmd.Run(); e != nil {
		if out.over || errout.over {
			return nil, ErrLimit
		}
		return nil, ErrDenied
	}
	return out.b.Bytes(), nil
}
func evaluate(data []byte, p contracts.BuildPolicy, digest string, now time.Time) (int, int, error) {
	if len(data) > 16<<20 || p.Validate(now) != nil {
		return 0, 0, ErrDenied
	}
	var report struct {
		SchemaVersion int `json:"SchemaVersion"`
		Metadata      struct {
			OS *struct {
				Family string `json:"Family"`
				Name   string `json:"Name"`
				EOSL   bool   `json:"EOSL"`
			} `json:"OS"`
		} `json:"Metadata"`
		Results []struct {
			Class           string `json:"Class"`
			Type            string `json:"Type"`
			Vulnerabilities []struct {
				ID       string `json:"VulnerabilityID"`
				Package  string `json:"PkgName"`
				Severity string `json:"Severity"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	if !utf8.Valid(data) || validateReportJSON(data) != nil {
		return 0, 0, ErrDenied
	}
	if json.Unmarshal(data, &report) != nil || report.SchemaVersion != 2 || report.Metadata.OS == nil || report.Metadata.OS.Family == "" || report.Metadata.OS.Name == "" || report.Metadata.OS.EOSL || len(report.Results) == 0 {
		return 0, 0, ErrDenied
	}
	high, critical, denied := 0, 0, false
	for _, result := range report.Results {
		if result.Class != "os-pkgs" && result.Class != "lang-pkgs" {
			return 0, 0, ErrDenied
		}
		if result.Type == "" {
			return 0, 0, ErrDenied
		}
		for _, v := range result.Vulnerabilities {
			if v.ID == "" || v.Package == "" {
				return 0, 0, ErrDenied
			}
			switch v.Severity {
			case "HIGH":
				high++
			case "CRITICAL":
				critical++
			case "LOW", "MEDIUM":
				continue
			default:
				return 0, 0, ErrDenied
			}
			excepted := false
			for _, ex := range p.Exceptions {
				if ex.Digest == digest && ex.Vulnerability == v.ID && ex.Package == v.Package && now.Before(ex.ExpiresAt) {
					excepted = true
				}
			}
			if !excepted {
				denied = true
			}
		}
	}
	if denied {
		return high, critical, ErrDenied
	}
	return high, critical, nil
}
func digestReader(r io.Reader) (string, error) {
	h := sha256.New()
	_, e := io.Copy(h, r)
	if e != nil {
		return "", e
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func validateReportJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	first, e := d.Token()
	if e != nil || first != json.Delim('{') {
		return ErrDenied
	}
	var walk func(json.Token, int) error
	walk = func(token json.Token, depth int) error {
		if depth > 32 {
			return ErrDenied
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return ErrDenied
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return ErrDenied
				}
				seen[name] = true
				value, e := d.Token()
				if e != nil {
					return ErrDenied
				}
				if e = walk(value, depth+1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return ErrDenied
			}
		case json.Delim('['):
			for d.More() {
				value, e := d.Token()
				if e != nil {
					return ErrDenied
				}
				if e = walk(value, depth+1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return ErrDenied
			}
		default:
			if n, ok := token.(json.Number); ok && len(n) > 32 {
				return ErrDenied
			}
		}
		return nil
	}
	if e = walk(first, 1); e != nil {
		return e
	}
	if _, e = d.Token(); e != io.EOF {
		return ErrDenied
	}
	return nil
}
