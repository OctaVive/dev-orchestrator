package contracts

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"time"
)

type BuildAuthorization struct {
	Job      BuildJob `json:"job"`
	ObjectID string   `json:"object_id"`
	Token    string   `json:"token"`
}

func (a BuildAuthorization) Validate(clone CloneJob, now time.Time) error {
	x, _ := json.Marshal(clone)
	y, _ := json.Marshal(a.Job.Clone)
	if a.Job.Validate(now) != nil || clone.Build == nil || !bytes.Equal(x, y) || len(a.ObjectID) != 32 || !cloneHash.MatchString(a.Token) {
		return ErrInvalidRequest
	}
	for _, c := range a.ObjectID {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ErrInvalidRequest
		}
	}
	return nil
}
func DecodeBuildAuthorization(r io.Reader, j CloneJob, now time.Time) (BuildAuthorization, error) {
	b, e := readObject(r, MaxBuildJobBytes+512)
	if e != nil {
		return BuildAuthorization{}, e
	}
	if e = exactCloneFields(b, reflect.TypeOf(BuildAuthorization{})); e != nil {
		return BuildAuthorization{}, e
	}
	a, e := decodeTyped[BuildAuthorization](b)
	if e != nil {
		return a, e
	}
	return a, a.Validate(j, now)
}

type BuildResult struct {
	Reason     string `json:"reason,omitempty"`
	JobID      string `json:"job_id"`
	PolicyHash string `json:"policy_hash"`
	Outcome    string `json:"outcome"`
}

func DecodeBuildResult(r io.Reader, j BuildJob) (BuildResult, error) {
	b, e := readObject(r, 1024)
	if e != nil {
		return BuildResult{}, e
	}
	if e = exactCloneFields(b, reflect.TypeOf(BuildResult{})); e != nil {
		return BuildResult{}, e
	}
	result, e := decodeTyped[BuildResult](b)
	if e != nil || result.JobID != j.Clone.JobID || result.PolicyHash != j.PolicyHash {
		return result, ErrInvalidRequest
	}
	switch result.Reason {
	case "", "context", "policy", "daemon", "build", "export", "upload":
	default:
		return result, ErrInvalidRequest
	}
	switch result.Outcome {
	case "exported", "denied", "limit", "timeout", "cancelled", "error":
		return result, nil
	}
	return result, ErrInvalidRequest
}
