package contracts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"
)

const MaxCloneJobBytes = 16 << 10
const MaxCloneResultBytes = MaxPlanBytes + 4096

var cloneID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var cloneHash = regexp.MustCompile(`^[0-9a-f]{64}$`)
var gitSHA1 = regexp.MustCompile(`^[0-9a-f]{40}$`)

// CloneLimits is operator policy, never a repository-controlled request.
type CloneLimits struct {
	Seconds            int   `json:"seconds"`
	AdvertisementBytes int64 `json:"advertisement_bytes"`
	Refs               int   `json:"refs"`
	TransferBytes      int64 `json:"transfer_bytes"`
	Objects            int   `json:"objects"`
	ObjectBytes        int64 `json:"object_bytes"`
	ExpandedBytes      int64 `json:"expanded_bytes"`
	Entries            int   `json:"entries"`
	Depth              int   `json:"depth"`
	PathBytes          int   `json:"path_bytes"`
	ContextBytes       int64 `json:"context_bytes"`
}

func DefaultCloneLimits() CloneLimits {
	return CloneLimits{300, 4 << 20, 4096, 256 << 20, 100000, 64 << 20, 2 << 30, 50000, 32, 1024, 1 << 30}
}

func (l CloneLimits) Validate() error {
	if l.Seconds < 1 || l.Seconds > 600 || l.AdvertisementBytes < 1024 || l.AdvertisementBytes > 16<<20 ||
		l.Refs < 1 || l.Refs > 16384 || l.TransferBytes < 1024 || l.TransferBytes > 1<<30 ||
		l.Objects < 1 || l.Objects > 200000 || l.ObjectBytes < 1 || l.ObjectBytes > 128<<20 ||
		l.ExpandedBytes < 1 || l.ExpandedBytes > 4<<30 || l.Entries < 1 || l.Entries > 100000 ||
		l.Depth < 1 || l.Depth > 64 || l.PathBytes < 1 || l.PathBytes > 4096 || l.ContextBytes < 1 || l.ContextBytes > 2<<30 {
		return ErrInvalidRequest
	}
	return nil
}

type ClonePolicy struct {
	Version int         `json:"version"`
	Hosts   []string    `json:"hosts"`
	Limits  CloneLimits `json:"limits"`
}

func (p ClonePolicy) Validate() error {
	if p.Version != 1 || len(p.Hosts) > 64 || p.Limits.Validate() != nil {
		return ErrInvalidRequest
	}
	seen := map[string]bool{}
	for _, h := range p.Hosts {
		if !validPublicHostnameShape(h) || seen[h] {
			return ErrInvalidRequest
		}
		seen[h] = true
	}
	return nil
}
func (p ClonePolicy) Hash() string {
	b, _ := json.Marshal(p)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type CloneJob struct {
	Configuration  *ConfigurationSettings `json:"configuration,omitempty"`
	Build          *BuildSettings         `json:"build,omitempty"`
	Version        int                    `json:"version"`
	JobID          string                 `json:"job_id"`
	DeploymentID   string                 `json:"deployment_id"`
	LeaseID        string                 `json:"lease_id"`
	Attempt        int64                  `json:"attempt"`
	Generation     int64                  `json:"generation"`
	ExpiresAt      time.Time              `json:"expires_at"`
	TemplateDigest string                 `json:"template_digest"`
	PolicyHash     string                 `json:"policy_hash"`
	RepositoryURL  string                 `json:"repository_url"`
	Branch         string                 `json:"branch"`
	ConfigPath     string                 `json:"config_path"`
	BuildContext   string                 `json:"build_context"`
	Policy         ClonePolicy            `json:"policy"`
}

func (j CloneJob) Validate(now time.Time) error {
	if j.Configuration != nil && (j.Configuration.Version != 1 || (j.Configuration.Mode != "dockerfile" && j.Configuration.Mode != "compose") || !ValidDigest(j.Configuration.PolicyHash) || j.Build == nil) {
		return ErrInvalidRequest
	}
	if j.Build != nil && j.Build.Validate(now) != nil {
		return ErrInvalidRequest
	}
	if ((j.Configuration == nil && j.Version != 1) || (j.Configuration != nil && j.Version != 2)) || !cloneID.MatchString(j.JobID) || !cloneID.MatchString(j.DeploymentID) ||
		!cloneID.MatchString(j.LeaseID) || j.Attempt < 1 || j.Generation < 1 || j.Attempt > 9007199254740991 || j.Generation > 9007199254740991 ||
		now.IsZero() || !j.ExpiresAt.After(now) || j.ExpiresAt.After(now.Add(30*time.Minute)) ||
		!strings.HasPrefix(j.TemplateDigest, "sha256:") || !cloneHash.MatchString(strings.TrimPrefix(j.TemplateDigest, "sha256:")) ||
		j.Policy.Validate() != nil || j.PolicyHash != j.Policy.Hash() ||
		!ValidCloneInput(j.RepositoryURL, j.Branch, j.ConfigPath, j.BuildContext) {
		return ErrInvalidRequest
	}
	u, _ := url.Parse(j.RepositoryURL)
	for _, h := range j.Policy.Hosts {
		if h == u.Hostname() {
			return nil
		}
	}
	return ErrInvalidRequest
}

// ValidCloneInput is shared with browser intent validation. Network destination
// validation remains the external broker's responsibility.
func ValidCloneInput(repo, branch, config, context string) bool {
	return len(repo) <= 2048 && len(branch) <= 255 && validRepositoryURL(repo) && validBranch(branch) &&
		ClonePath(config, false) && ClonePath(context, true)
}
func ClonePath(p string, root bool) bool {
	if p == "." {
		return root
	}
	if len(p) == 0 || len(p) > 4096 || strings.ContainsAny(p, "\\\x00:\r\n\t") || strings.HasPrefix(p, "/") {
		return false
	}
	for _, s := range strings.Split(p, "/") {
		if s == "" || s == "." || s == ".." || strings.EqualFold(s, ".git") || strings.HasSuffix(s, ".") || strings.HasSuffix(s, " ") {
			return false
		}
		for _, c := range s {
			if c < 32 || c == 127 {
				return false
			}
		}
	}
	return true
}
func DecodeCloneJob(r io.Reader, now time.Time) (CloneJob, error) {
	b, e := readObject(r, MaxCloneJobBytes)
	if e != nil {
		return CloneJob{}, e
	}
	if e = exactCloneFields(b, reflect.TypeOf(CloneJob{})); e != nil {
		return CloneJob{}, e
	}
	j, e := decodeTyped[CloneJob](b)
	if e != nil {
		return CloneJob{}, e
	}
	return j, j.Validate(now)
}

// CloneResult is untrusted guest data, even when all identity fields match.
type CloneResult struct {
	Plan           *ConfigurationPlan `json:"plan,omitempty"`
	Version        int                `json:"version"`
	JobID          string             `json:"job_id"`
	DeploymentID   string             `json:"deployment_id"`
	LeaseID        string             `json:"lease_id"`
	Attempt        int64              `json:"attempt"`
	Generation     int64              `json:"generation"`
	PolicyHash     string             `json:"policy_hash"`
	TemplateDigest string             `json:"template_digest"`
	SHA            string             `json:"sha,omitempty"`
	ObjectFormat   string             `json:"object_format"`
	Outcome        string             `json:"outcome"`
	ContextID      string             `json:"context_id,omitempty"`
	Entries        int                `json:"entries"`
	Bytes          int64              `json:"bytes"`
}

func NewCloneResult(j CloneJob) CloneResult {
	return CloneResult{Version: j.Version, JobID: j.JobID, DeploymentID: j.DeploymentID, LeaseID: j.LeaseID, Attempt: j.Attempt, Generation: j.Generation, PolicyHash: j.PolicyHash, TemplateDigest: j.TemplateDigest, ObjectFormat: "sha1", Outcome: "error"}
}
func ValidSHA1(s string) bool { return gitSHA1.MatchString(s) && s != strings.Repeat("0", 40) }
func (r CloneResult) Validate(j CloneJob) error {
	if r.Version != j.Version || r.JobID != j.JobID || r.DeploymentID != j.DeploymentID || r.LeaseID != j.LeaseID || r.Attempt != j.Attempt || r.Generation != j.Generation ||
		r.PolicyHash != j.PolicyHash || r.TemplateDigest != j.TemplateDigest || r.ObjectFormat != "sha1" || r.Entries < 0 || r.Entries > j.Policy.Limits.Entries || r.Bytes < 0 || r.Bytes > j.Policy.Limits.ContextBytes ||
		r.SHA != "" && !ValidSHA1(r.SHA) {
		return ErrInvalidRequest
	}
	if r.Plan != nil && (j.Configuration == nil || r.Outcome != "success" || r.Plan.PolicyHash != j.Configuration.PolicyHash) {
		return ErrInvalidRequest
	}
	if j.Configuration != nil && r.Outcome == "success" && r.Plan == nil {
		return ErrInvalidRequest
	}
	switch r.Outcome {
	case "resolved":
		if !ValidSHA1(r.SHA) || r.ContextID != "" {
			return ErrInvalidRequest
		}
	case "success":
		if !ValidSHA1(r.SHA) || !cloneHash.MatchString(r.ContextID) || r.Entries < 1 {
			return ErrInvalidRequest
		}
	case "error", "denied", "limit", "timeout", "cancelled":
		if r.ContextID != "" {
			return ErrInvalidRequest
		}
	default:
		return ErrInvalidRequest
	}
	return nil
}
func DecodeCloneResult(rd io.Reader, j CloneJob) (CloneResult, error) {
	b, e := readObject(rd, MaxCloneResultBytes)
	if e != nil {
		return CloneResult{}, e
	}
	if e = exactCloneFields(b, reflect.TypeOf(CloneResult{})); e != nil {
		return CloneResult{}, e
	}
	r, e := decodeTyped[CloneResult](b)
	if e != nil {
		return CloneResult{}, e
	}
	return r, r.Validate(j)
}

// encoding/json matches struct names case-insensitively. The clone wire
// contract instead requires exact JSON tags, including nested policy fields.
func exactCloneFields(b []byte, t reflect.Type) error {
	if t.Kind() == reflect.Pointer {
		if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
			return ErrSchema
		}
		return exactCloneFields(b, t.Elem())
	}
	if t.Kind() == reflect.Map {
		var m map[string]json.RawMessage
		if json.Unmarshal(b, &m) != nil {
			return ErrSchema
		}
		for _, v := range m {
			if e := exactCloneFields(v, t.Elem()); e != nil {
				return e
			}
		}
		return nil
	}
	if t == reflect.TypeOf(time.Time{}) {
		return nil
	}
	if t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
		var values []json.RawMessage
		if json.Unmarshal(b, &values) != nil {
			return ErrSchema
		}
		for _, value := range values {
			if e := exactCloneFields(value, t.Elem()); e != nil {
				return e
			}
		}
		return nil
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	var values map[string]json.RawMessage
	if json.Unmarshal(b, &values) != nil || values == nil {
		return ErrSchema
	}
	fields := map[string]reflect.Type{}
	for n := 0; n < t.NumField(); n++ {
		field := t.Field(n)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if field.PkgPath != "" || name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = field.Type
	}
	for key, value := range values {
		field, ok := fields[key]
		if !ok {
			return ErrSchema
		}
		if e := exactCloneFields(value, field); e != nil {
			return e
		}
	}
	return nil
}
