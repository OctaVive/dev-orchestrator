package contracts

import (
	"io"
	"time"
)

const (
	MaxBuildLeaseBytes = 16 << 10
	MaxBuildLifetime   = 30 * time.Minute
)

// BuildLeaseRequest deliberately has no host path, XML, network, image URL,
// shell, secret or caller-selected controller identity. Template/profile IDs
// are resolved and revalidated by the host-side provisioner.
type BuildLeaseRequest struct {
	SchemaVersion int       `json:"schema_version"`
	CommandID     string    `json:"command_id"`
	JobID         string    `json:"job_id"`
	AppID         string    `json:"app_id"`
	DeploymentID  string    `json:"deployment_id"`
	TemplateID    string    `json:"template_id"`
	ProfileID     string    `json:"profile_id"`
	Nonce         string    `json:"nonce"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func (v *Validator) DecodeBuildLease(r io.Reader, now time.Time) (BuildLeaseRequest, error) {
	b, err := readObject(r, MaxBuildLeaseBytes)
	if err != nil {
		return BuildLeaseRequest{}, err
	}
	if err := validateSchema(v.buildLease, b); err != nil {
		return BuildLeaseRequest{}, err
	}
	request, err := decodeTyped[BuildLeaseRequest](b)
	if err != nil {
		return BuildLeaseRequest{}, err
	}
	if now.IsZero() || !request.ExpiresAt.After(now) || request.ExpiresAt.After(now.Add(MaxBuildLifetime)) {
		return BuildLeaseRequest{}, ErrCommandContext
	}
	request.ExpiresAt = request.ExpiresAt.UTC()
	return request, nil
}

// DecodeEmptyObject accepts only {} for idempotent release operations.
func DecodeEmptyObject(r io.Reader) error {
	b, err := readObject(r, 1024)
	if err != nil {
		return err
	}
	_, err = decodeTyped[struct{}](b)
	return err
}
