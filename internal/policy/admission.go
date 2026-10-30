package policy

import (
	"dev-orchestrator/internal/contracts"
	"time"
)

// FromArtifact bridges an immutable M07 admission record to M08 policy.
// The caller must obtain result and job from its trusted durable store.
func FromArtifact(image string, j contracts.BuildJob, r contracts.ArtifactResult) (Admission, error) {
	if j.Policy.Validate(time.Now()) != nil || r.Validate(j) != nil || r.Outcome != "admitted" || r.Metadata == nil || !ValidImage(image) || image[len(image)-71:] != r.ImageDigest {
		return Admission{}, ErrAdmission
	}
	m := r.Metadata
	return Admission{SourceSHA: j.SHA, ContextID: j.ContextID, DeploymentID: j.Clone.DeploymentID, ID: contracts.ConfigurationDigest(r), Image: image, PolicyHash: Hash(), Platform: m.Platform, User: m.User, Command: m.Command, Entrypoint: m.Entrypoint, Environment: m.Environment, Expose: m.Expose}, nil
}
