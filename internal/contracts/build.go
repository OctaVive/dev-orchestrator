package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"reflect"
	"strings"
	"time"
)

const MaxBuildJobBytes = 32 << 10
const MaxBuildResultBytes = 8192

// ArtifactLimits are operator-owned. All allocation/expansion limits must be
// enforced while streaming, inside the disposable ingest VM.
type ArtifactLimits struct {
	UploadBytes   int64 `json:"upload_bytes"`
	ExpandedBytes int64 `json:"expanded_bytes"`
	LayerBytes    int64 `json:"layer_bytes"`
	Entries       int   `json:"entries"`
	Descriptors   int   `json:"descriptors"`
	JSONBytes     int64 `json:"json_bytes"`
	PathBytes     int   `json:"path_bytes"`
	Depth         int   `json:"depth"`
	Ratio         int64 `json:"ratio"`
}

func DefaultArtifactLimits() ArtifactLimits {
	return ArtifactLimits{1 << 30, 4 << 30, 2 << 30, 100000, 256, 4 << 20, 1024, 64, 100}
}
func (l ArtifactLimits) Validate() error {
	if l.UploadBytes < 1024 || l.UploadBytes > 1<<30 || l.ExpandedBytes < 1024 || l.ExpandedBytes > 4<<30 || l.LayerBytes < 512 || l.LayerBytes > 2<<30 || l.Entries < 1 || l.Entries > 100000 || l.Descriptors < 1 || l.Descriptors > 256 || l.JSONBytes < 128 || l.JSONBytes > 4<<20 || l.PathBytes < 1 || l.PathBytes > 1024 || l.Depth < 1 || l.Depth > 64 || l.Ratio < 1 || l.Ratio > 100 {
		return ErrInvalidRequest
	}
	return nil
}

type ScanException struct {
	Vulnerability string    `json:"vulnerability"`
	Package       string    `json:"package"`
	Digest        string    `json:"digest"`
	ExpiresAt     time.Time `json:"expires_at"`
}
type BuildSettings struct {
	Policy     BuildPolicy `json:"policy"`
	Dockerfile string      `json:"dockerfile"`
}

func (s BuildSettings) Validate(now time.Time) error {
	if s.Policy.Validate(now) != nil || !ClonePath(s.Dockerfile, false) {
		return ErrInvalidRequest
	}
	return nil
}

type BuildPolicy struct {
	EgressPolicyHash      string          `json:"egress_policy_hash"`
	UploadOrigin          string          `json:"upload_origin"`
	Version               int             `json:"version"`
	BuildSeconds          int             `json:"build_seconds"`
	ScanSeconds           int             `json:"scan_seconds"`
	Limits                ArtifactLimits  `json:"limits"`
	ScannerDigest         string          `json:"scanner_digest"`
	DatabaseDigest        string          `json:"database_digest"`
	DatabaseCreatedAt     time.Time       `json:"database_created_at"`
	DatabaseMaxAgeSeconds int             `json:"database_max_age_seconds"`
	Exceptions            []ScanException `json:"exceptions"`
}

func Digest(b []byte) string   { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
func ValidJobID(s string) bool { return cloneID.MatchString(s) }
func ValidDigest(s string) bool {
	return len(s) == 71 && strings.HasPrefix(s, "sha256:") && cloneHash.MatchString(s[7:])
}
func (p BuildPolicy) Hash() string { b, _ := json.Marshal(p); return Digest(b) }
func (p BuildPolicy) Validate(now time.Time) error {
	u, e := url.Parse(p.UploadOrigin)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || !validPublicHostnameShape(u.Hostname()) {
		return ErrInvalidRequest
	}

	if !cloneHash.MatchString(p.EgressPolicyHash) || p.Version != 1 || p.BuildSeconds < 1 || p.BuildSeconds > 1200 || p.ScanSeconds < 1 || p.ScanSeconds > 300 || p.Limits.Validate() != nil || !ValidDigest(p.ScannerDigest) || !ValidDigest(p.DatabaseDigest) || p.DatabaseCreatedAt.IsZero() || p.DatabaseCreatedAt.After(now) || p.DatabaseMaxAgeSeconds < 1 || p.DatabaseMaxAgeSeconds > 172800 || now.Sub(p.DatabaseCreatedAt) > time.Duration(p.DatabaseMaxAgeSeconds)*time.Second || len(p.Exceptions) > 16 {
		return ErrInvalidRequest
	}
	for _, e := range p.Exceptions {
		if e.Vulnerability == "" || len(e.Vulnerability) > 128 || e.Package == "" || len(e.Package) > 256 || !ValidDigest(e.Digest) || !e.ExpiresAt.After(now) || e.ExpiresAt.After(now.Add(30*24*time.Hour)) {
			return ErrInvalidRequest
		}
	}
	return nil
}

type BuildJob struct {
	Version    int         `json:"version"`
	Clone      CloneJob    `json:"clone"`
	SHA        string      `json:"sha"`
	ContextID  string      `json:"context_id"`
	Policy     BuildPolicy `json:"policy"`
	PolicyHash string      `json:"policy_hash"`
	Dockerfile string      `json:"dockerfile"`
	ExpiresAt  time.Time   `json:"expires_at"`
}

func (j BuildJob) Validate(now time.Time) error {
	if j.Clone.Build == nil || j.Clone.Build.Policy.Hash() != j.PolicyHash || j.Clone.Build.Dockerfile != j.Dockerfile {
		return ErrInvalidRequest
	}

	if j.Version != 1 || j.Clone.Validate(now) != nil || !ValidSHA1(j.SHA) || !cloneHash.MatchString(j.ContextID) || j.Policy.Validate(now) != nil || j.PolicyHash != j.Policy.Hash() || !ClonePath(j.Dockerfile, false) || !j.ExpiresAt.After(now) || j.ExpiresAt.After(j.Clone.ExpiresAt) {
		return ErrInvalidRequest
	}
	return nil
}
func DecodeBuildJob(r io.Reader, now time.Time) (BuildJob, error) {
	b, e := readObject(r, MaxBuildJobBytes)
	if e != nil {
		return BuildJob{}, e
	}
	if e = exactCloneFields(b, reflect.TypeOf(BuildJob{})); e != nil {
		return BuildJob{}, e
	}
	j, e := decodeTyped[BuildJob](b)
	if e != nil {
		return j, e
	}
	return j, j.Validate(now)
}

// ArtifactResult contains only normalized evidence. Raw tool diagnostics, URLs,
// paths, credentials and repository-controlled finding text are excluded.
type ArtifactResult struct {
	Version        int    `json:"version"`
	JobID          string `json:"job_id"`
	DeploymentID   string `json:"deployment_id"`
	Attempt        int64  `json:"attempt"`
	Generation     int64  `json:"generation"`
	PolicyHash     string `json:"policy_hash"`
	ArchiveDigest  string `json:"archive_digest"`
	ImageDigest    string `json:"image_digest"`
	ScannerDigest  string `json:"scanner_digest"`
	DatabaseDigest string `json:"database_digest"`
	ReportDigest   string `json:"report_digest"`
	SBOMDigest     string `json:"sbom_digest"`
	Outcome        string `json:"outcome"`
	High           int    `json:"high"`
	Critical       int    `json:"critical"`
}

func (r ArtifactResult) Validate(j BuildJob) error {
	if r.Version != 1 || r.JobID != j.Clone.JobID || r.DeploymentID != j.Clone.DeploymentID || r.Attempt != j.Clone.Attempt || r.Generation != j.Clone.Generation || r.PolicyHash != j.PolicyHash || r.High < 0 || r.Critical < 0 || r.High > 100000 || r.Critical > 100000 {
		return ErrInvalidRequest
	}
	for _, digest := range []string{r.ArchiveDigest, r.ImageDigest, r.ScannerDigest, r.DatabaseDigest, r.ReportDigest, r.SBOMDigest} {
		if digest != "" && !ValidDigest(digest) {
			return ErrInvalidRequest
		}
	}
	switch r.Outcome {
	case "admitted":
		if !ValidDigest(r.ArchiveDigest) || !ValidDigest(r.ImageDigest) || r.ScannerDigest != j.Policy.ScannerDigest || r.DatabaseDigest != j.Policy.DatabaseDigest || !ValidDigest(r.ReportDigest) || !ValidDigest(r.SBOMDigest) {
			return ErrInvalidRequest
		}
	case "denied", "limit", "timeout", "cancelled", "error":
		if r.ImageDigest != "" {
			return ErrInvalidRequest
		}
	default:
		return ErrInvalidRequest
	}
	return nil
}

// ReadJSONObject validates size, UTF-8, duplicate keys, depth and integer
// encodings before an isolated parser interprets an OCI JSON document.
func ReadJSONObject(r io.Reader, limit int64) ([]byte, error) { return readObject(r, limit) }

// IngestJob selects only an opaque quarantine object; it never supplies a path.
type IngestJob struct {
	Build         BuildJob `json:"build"`
	ObjectID      string   `json:"object_id"`
	Bytes         int64    `json:"bytes"`
	ArchiveDigest string   `json:"archive_digest"`
}

func (j IngestJob) Validate(now time.Time) error {
	if j.Build.Validate(now) != nil || len(j.ObjectID) != 32 || j.Bytes < 1 || j.Bytes > j.Build.Policy.Limits.UploadBytes || !ValidDigest(j.ArchiveDigest) {
		return ErrInvalidRequest
	}
	for _, c := range j.ObjectID {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ErrInvalidRequest
		}
	}
	return nil
}
func DecodeArtifactResult(r io.Reader, j BuildJob) (ArtifactResult, error) {
	b, e := readObject(r, MaxBuildResultBytes)
	if e != nil {
		return ArtifactResult{}, e
	}
	if e = exactCloneFields(b, reflect.TypeOf(ArtifactResult{})); e != nil {
		return ArtifactResult{}, e
	}
	result, e := decodeTyped[ArtifactResult](b)
	if e != nil {
		return result, e
	}
	return result, result.Validate(j)
}

func ValidObjectID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
