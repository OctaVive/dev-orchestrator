// Package contracts validates data shape at trust boundaries. It does not
// authorize deployments or provide a safe execution environment.
package contracts

import "time"

type DeploymentRequest struct {
	SchemaVersion  int               `json:"schema_version"`
	AppID          string            `json:"app_id"`
	RepositoryURL  string            `json:"repository_url"`
	Branch         string            `json:"branch"`
	DeploymentType string            `json:"deployment_type"`
	ConfigPath     string            `json:"config_path"`
	BuildContext   string            `json:"build_context"`
	Environment    map[string]string `json:"environment,omitempty"`
	Volumes        []Mount           `json:"volumes,omitempty"`
}

type Mount struct {
	VolumeID string `json:"volume_id"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}

type Resources struct {
	CPUMillis     int   `json:"cpu_millis"`
	MemoryBytes   int64 `json:"memory_bytes"`
	PIDs          int   `json:"pids"`
	TmpBytes      int64 `json:"tmp_bytes"`
	WritableBytes int64 `json:"writable_bytes"`
	LogBytes      int64 `json:"log_bytes"`
}

type Service struct {
	Name        string            `json:"name"`
	Image       string            `json:"image"`
	UID         int               `json:"uid"`
	GID         int               `json:"gid"`
	Command     []string          `json:"command,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	Volumes     []Mount           `json:"volumes,omitempty"`
	Resources   Resources         `json:"resources"`
}

type Ingress struct {
	Service    string `json:"service"`
	Port       int    `json:"port"`
	HealthPath string `json:"health_path"`
}

// Restricted-v1 fixes dropped capabilities, no-new-privileges, read-only root,
// seccomp, private namespaces, no host ports and default-deny networking in
// backend policy. These are not caller-switchable booleans.
type RuntimeSpec struct {
	Profile  string    `json:"profile"`
	Services []Service `json:"services"`
	Ingress  Ingress   `json:"ingress"`
}

// AgentCommand is only a structurally validated envelope. No command may be
// executed until a future agent verifies its signature and durable replay state.
type AgentCommand struct {
	SchemaVersion int         `json:"schema_version"`
	CommandID     string      `json:"command_id"`
	Action        string      `json:"action"`
	AppID         string      `json:"app_id"`
	DeploymentID  string      `json:"deployment_id"`
	WorkerID      string      `json:"worker_id"`
	Generation    int64       `json:"generation"`
	ExpiresAt     time.Time   `json:"expires_at"`
	Nonce         string      `json:"nonce"`
	PolicyHash    string      `json:"policy_hash"`
	KeyID         string      `json:"key_id"`
	Signature     string      `json:"signature"`
	Spec          RuntimeSpec `json:"spec"`
}
