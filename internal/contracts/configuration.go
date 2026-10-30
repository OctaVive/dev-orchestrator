package contracts

import (
	"encoding/json"
	"io"
	"reflect"
)

const MaxConfigurationBytes = 256 << 10
const MaxPlanBytes = 64 << 10

// ConfigurationSettings is sealed before clone; repositories cannot select policy.
type ConfigurationSettings struct {
	Version    int    `json:"version"`
	Mode       string `json:"mode"`
	PolicyHash string `json:"policy_hash"`
}
type LocalBuild struct {
	Context          string `json:"context"`
	Dockerfile       string `json:"dockerfile"`
	DockerfileDigest string `json:"dockerfile_digest"`
}
type Healthcheck struct {
	Argv            []string `json:"argv"`
	IntervalSeconds int      `json:"interval_seconds"`
	TimeoutSeconds  int      `json:"timeout_seconds"`
	Retries         int      `json:"retries"`
}
type PlannedMount struct {
	Name     string `json:"name"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}
type PlannedService struct {
	Name            string            `json:"name"`
	Image           string            `json:"image,omitempty"`
	Build           *LocalBuild       `json:"build,omitempty"`
	Command         []string          `json:"command,omitempty"`
	Entrypoint      []string          `json:"entrypoint,omitempty"`
	Environment     map[string]string `json:"environment,omitempty"`
	Expose          []int             `json:"expose,omitempty"`
	DependsOn       []string          `json:"depends_on,omitempty"`
	Mounts          []PlannedMount    `json:"mounts,omitempty"`
	Resources       Resources         `json:"resources"`
	RestartAttempts int               `json:"restart_attempts"`
	Health          *Healthcheck      `json:"health,omitempty"`
}

// ConfigurationPlan is untrusted even when its digest matches. Validate it at
// every consumer; neither a guest identity nor a hash grants deployment rights.
type ConfigurationPlan struct {
	Version      int              `json:"version"`
	PolicyHash   string           `json:"policy_hash"`
	ConfigDigest string           `json:"config_digest"`
	Services     []PlannedService `json:"services"`
}
type RuntimeServiceV2 struct {
	Name            string            `json:"name"`
	Image           string            `json:"image"`
	AdmissionID     string            `json:"admission_id"`
	UID             int               `json:"uid"`
	GID             int               `json:"gid"`
	Command         []string          `json:"command,omitempty"`
	Entrypoint      []string          `json:"entrypoint,omitempty"`
	Environment     map[string]string `json:"environment,omitempty"`
	Expose          []int             `json:"expose,omitempty"`
	DependsOn       []string          `json:"depends_on,omitempty"`
	Volumes         []Mount           `json:"volumes,omitempty"`
	Secrets         []SecretReference `json:"secrets,omitempty"`
	Resources       Resources         `json:"resources"`
	RestartAttempts int               `json:"restart_attempts"`
	Health          *Healthcheck      `json:"health,omitempty"`
}
type SecretReference struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Target  string `json:"target"`
}
type RuntimeSpecV2 struct {
	Version      int                `json:"version"`
	Profile      string             `json:"profile"`
	PolicyHash   string             `json:"policy_hash"`
	AppID        string             `json:"app_id"`
	DeploymentID string             `json:"deployment_id"`
	SHA          string             `json:"sha"`
	ContextID    string             `json:"context_id"`
	PlanHash     string             `json:"plan_hash"`
	Services     []RuntimeServiceV2 `json:"services"`
	Ingress      Ingress            `json:"ingress"`
}
type AgentCommandV2 struct {
	SchemaVersion int           `json:"schema_version"`
	CommandID     string        `json:"command_id"`
	WorkerID      string        `json:"worker_id"`
	Generation    int64         `json:"generation"`
	ExpiresAt     string        `json:"expires_at"`
	Nonce         string        `json:"nonce"`
	KeyID         string        `json:"key_id"`
	Signature     string        `json:"signature"`
	SpecHash      string        `json:"spec_hash"`
	Spec          RuntimeSpecV2 `json:"spec"`
}

// DecodeConfiguration strictly checks byte/depth/duplicate/integer limits and
// exact JSON field spelling, including fields nested in pointers and slices.
func DecodeConfiguration[T any](r io.Reader) (T, error) {
	var z T
	b, e := readObject(r, MaxPlanBytes)
	if e != nil {
		return z, e
	}
	if e = exactCloneFields(b, reflect.TypeOf(z)); e != nil {
		return z, e
	}
	return decodeTyped[T](b)
}
func ConfigurationDigest(v any) string { b, _ := json.Marshal(v); return Digest(b) }

// ImageMetadata is emitted only by isolated digest validation and carried in the
// immutable admission record. It is not a browser or builder assertion.
type ImageMetadata struct {
	User        string            `json:"user"`
	Platform    string            `json:"platform"`
	Command     []string          `json:"command,omitempty"`
	Entrypoint  []string          `json:"entrypoint,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	Expose      []int             `json:"expose,omitempty"`
}
