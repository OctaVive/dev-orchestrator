// Package runtimeobservation defines fixed, read-only VM measurement messages.
// Requests select enrolled app/object identities, never paths, PIDs or commands.
package runtimeobservation

import (
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/runtimeisolation"
)

const Socket = "/run/tap-runtime/measure.sock"

type Request struct {
	Port         int                 `json:"port,omitempty"`
	Path         string              `json:"path,omitempty"`
	Operation    string              `json:"operation"`
	AppID        string              `json:"app_id"`
	ContainerID  string              `json:"container_id,omitempty"`
	OwnerID      string              `json:"owner_id,omitempty"`
	DeploymentID string              `json:"deployment_id,omitempty"`
	Generation   int64               `json:"generation,omitempty"`
	SpecHash     string              `json:"spec_hash,omitempty"`
	Service      string              `json:"service,omitempty"`
	UID          int                 `json:"uid,omitempty"`
	GID          int                 `json:"gid,omitempty"`
	Resources    contracts.Resources `json:"resources"`
}
type BackendProof struct {
	DiskBytes        int64  `json:"disk_bytes"`
	PhysicalBytes    int64  `json:"physical_bytes"`
	MemoryBytes      int64  `json:"memory_bytes"`
	CPUMillis        int    `json:"cpu_millis"`
	PIDs             int    `json:"pids"`
	NetworkNamespace string `json:"network_namespace"`
	NoUplink         bool   `json:"no_uplink"`
}
type Report struct {
	Health      *Health                              `json:"health,omitempty"`
	Version     int                                  `json:"version"`
	WorkerID    string                               `json:"worker_id"`
	Incarnation string                               `json:"incarnation"`
	AppID       string                               `json:"app_id"`
	BackendHash string                               `json:"backend_hash"`
	ProfileHash string                               `json:"profile_hash"`
	ContainerID string                               `json:"container_id,omitempty"`
	Backend     BackendProof                         `json:"backend"`
	Process     *runtimeisolation.ProcessMeasurement `json:"process,omitempty"`
}

type Health struct {
	Status     int    `json:"status"`
	BodyBase64 string `json:"body_base64"`
	SHA256     string `json:"sha256"`
}

// CanaryDescriptor pins a platform-owned immutable OCI fixture. It is separate
// from user admissions and cannot be selected or modified by an execution command.
type CanaryDescriptor struct {
	ArchiveDigest  string `json:"archive_digest"`
	Bytes          int64  `json:"bytes"`
	ImageID        string `json:"image_id"`
	ManifestDigest string `json:"manifest_digest"`
	BinaryDigest   string `json:"binary_digest"`
}

func (c CanaryDescriptor) Valid() bool {
	return contracts.ValidDigest(c.ArchiveDigest) && contracts.ValidDigest(c.ImageID) && contracts.ValidDigest(c.ManifestDigest) && contracts.ValidDigest(c.BinaryDigest) && c.Bytes > 0 && c.Bytes <= 16<<20
}

const CanaryArchive = "/usr/local/share/tap-runtime/canary.oci.tar"
