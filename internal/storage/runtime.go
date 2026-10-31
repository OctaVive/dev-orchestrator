package storage

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"dev-orchestrator/internal/artifacts"
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/policy"
	"dev-orchestrator/internal/runtimeagent"
	"dev-orchestrator/internal/runtimeauthority"
)

// RuntimeWorker is an explicitly enrolled identity and short controller lease.
// This method family is trusted controller code, never a browser/guest endpoint.
type RuntimeWorker struct {
	WorkerID, Incarnation string
	LeaseUntil            time.Time
	InventoryKey          ed25519.PublicKey
}

func (s *Store) EnrollRuntimeWorker(ctx context.Context, w RuntimeWorker) error {
	now := time.Now()
	if !validIDs(w.WorkerID, w.Incarnation) || !w.LeaseUntil.After(now) || w.LeaseUntil.After(now.Add(time.Minute)) || len(w.InventoryKey) != ed25519.PublicKeySize {
		return ErrInvalidInput
	}
	return s.write(ctx, func(c *sql.Conn) error {
		var inc string
		var key []byte
		var revoked int
		err := c.QueryRowContext(ctx, "SELECT incarnation,inventory_key,revoked FROM runtime_workers WHERE worker=?", w.WorkerID).Scan(&inc, &key, &revoked)
		if err == nil {
			if revoked != 0 || inc != w.Incarnation || string(key) != string(w.InventoryKey) {
				return ErrConflict
			}
			_, err = c.ExecContext(ctx, "UPDATE runtime_workers SET lease_until=? WHERE worker=? AND lease_until<=?", w.LeaseUntil.UnixNano(), w.WorkerID, w.LeaseUntil.UnixNano())
			return runtimeDBError(ctx, err)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return runtimeDBError(ctx, err)
		}
		_, err = c.ExecContext(ctx, "INSERT INTO runtime_workers(worker,incarnation,lease_until,inventory_key) VALUES(?,?,?,?)", w.WorkerID, w.Incarnation, w.LeaseUntil.UnixNano(), []byte(w.InventoryKey))
		return runtimeDBError(ctx, err)
	})
}
func (s *Store) EnrollRuntimeCertificate(ctx context.Context, worker, incarnation, fingerprint string, until time.Time) error {
	if !validIDs(worker, incarnation) || !contracts.ValidDigest("sha256:"+fingerprint) || !until.After(time.Now()) || until.After(time.Now().Add(24*time.Hour)) {
		return ErrInvalidInput
	}
	return s.write(ctx, func(c *sql.Conn) error {
		var n int
		if c.QueryRowContext(ctx, "SELECT count(*) FROM runtime_workers WHERE worker=? AND incarnation=? AND revoked=0", worker, incarnation).Scan(&n) != nil || n != 1 {
			return ErrConflict
		}
		var w, i string
		var u int64
		var revoked int
		err := c.QueryRowContext(ctx, "SELECT worker,incarnation,valid_until,revoked FROM runtime_certificates WHERE fingerprint=?", fingerprint).Scan(&w, &i, &u, &revoked)
		if err == nil {
			if w == worker && i == incarnation && u == until.UnixNano() && revoked == 0 {
				return nil
			}
			return ErrConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return runtimeDBError(ctx, err)
		}
		_, err = c.ExecContext(ctx, "INSERT INTO runtime_certificates(fingerprint,worker,incarnation,valid_until) VALUES(?,?,?,?)", fingerprint, worker, incarnation, until.UnixNano())
		return runtimeDBError(ctx, err)
	})
}
func (s *Store) EnrollRuntimeBackend(ctx context.Context, worker, incarnation, app, hash string) error {
	if !validIDs(worker, incarnation, app) || !contracts.ValidDigest(hash) {
		return ErrInvalidInput
	}
	return s.write(ctx, func(c *sql.Conn) error {
		var old string
		err := c.QueryRowContext(ctx, "SELECT backend_hash FROM runtime_backends WHERE worker=? AND incarnation=? AND app=?", worker, incarnation, app).Scan(&old)
		if err == nil {
			if old == hash {
				return nil
			}
			return ErrConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return runtimeDBError(ctx, err)
		}
		var n int
		if c.QueryRowContext(ctx, "SELECT count(*) FROM runtime_workers WHERE worker=? AND incarnation=? AND revoked=0", worker, incarnation).Scan(&n) != nil || n != 1 {
			return ErrConflict
		}
		_, err = c.ExecContext(ctx, "INSERT INTO runtime_backends VALUES(?,?,?,?)", worker, incarnation, app, hash)
		return runtimeDBError(ctx, err)
	})
}

// EnrollRuntimeImage reads the immutable M07 result from management storage.
// Callers cannot supply admitted image metadata, archive identities or scan flags.
func (s *Store) EnrollRuntimeImage(ctx context.Context, i BuildIntent, image string) (policy.Admission, error) {
	if !validIDs(i.Actor.ID, i.CorrelationID, i.Job.Clone.JobID) || (i.Actor.Kind != "controller" && i.Actor.Kind != "worker") {
		return policy.Admission{}, ErrInvalidInput
	}
	var a policy.Admission
	err := s.write(ctx, func(c *sql.Conn) error {
		// The completed record survives its build lease. Its exact immutable
		// job hash and admitted result authorize metadata reuse, never a build.
		var jobRaw, resultRaw string
		if c.QueryRowContext(ctx, "SELECT job_json,result_json FROM build_attempts WHERE job_id=? AND job_hash=? AND stage='admitted'", i.Job.Clone.JobID, buildHash(i.Job)).Scan(&jobRaw, &resultRaw) != nil {
			return ErrConflict
		}
		var job contracts.BuildJob
		var result contracts.ArtifactResult
		if json.Unmarshal([]byte(jobRaw), &job) != nil || json.Unmarshal([]byte(resultRaw), &result) != nil || buildHash(job) != buildHash(i.Job) {
			return ErrIntegrity
		}
		var admissionErr error
		a, admissionErr = policy.FromArtifact(image, job, result)
		if admissionErr != nil {
			return ErrInvalidInput
		}
		var current string
		if c.QueryRowContext(ctx, "SELECT policy_hash FROM runtime_scan_policy WHERE singleton=1").Scan(&current) != nil || current != i.Job.PolicyHash {
			return ErrConflict
		}
		var oldImage, enrolledJob string
		var revoked int
		err := c.QueryRowContext(ctx, "SELECT image,job_id,revoked FROM runtime_images WHERE admission=?", a.ID).Scan(&oldImage, &enrolledJob, &revoked)
		if err == nil {
			if oldImage == image && enrolledJob == i.Job.Clone.JobID && revoked == 0 {
				return nil
			}
			return ErrConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return runtimeDBError(ctx, err)
		}
		_, err = c.ExecContext(ctx, "INSERT INTO runtime_images(admission,image,job_id) VALUES(?,?,?)", a.ID, image, i.Job.Clone.JobID)
		return runtimeDBError(ctx, err)
	})
	return a, err
}
func runtimeImage(ctx context.Context, c *sql.Conn, id, image string) (runtimeauthority.Image, error) {
	var jobRaw, resultRaw string
	var bytes int64
	err := c.QueryRowContext(ctx, `SELECT b.job_json,b.result_json,b.archive_bytes FROM runtime_images a JOIN build_attempts b ON b.job_id=a.job_id JOIN runtime_scan_policy sp ON sp.singleton=1 AND sp.policy_hash=json_extract(b.job_json,'$.policy_hash') WHERE a.admission=? AND a.image=? AND a.revoked=0 AND b.stage='admitted'`, id, image).Scan(&jobRaw, &resultRaw, &bytes)
	if err != nil {
		return runtimeauthority.Image{}, runtimeagent.ErrDenied
	}
	var job contracts.BuildJob
	var result contracts.ArtifactResult
	if json.Unmarshal([]byte(jobRaw), &job) != nil || json.Unmarshal([]byte(resultRaw), &result) != nil {
		return runtimeauthority.Image{}, runtimeagent.ErrDenied
	}
	a, err := policy.FromArtifact(image, job, result)
	if err != nil || a.ID != id || bytes < 1 || bytes > 1<<30 {
		return runtimeauthority.Image{}, runtimeagent.ErrDenied
	}
	return runtimeauthority.Image{Admission: a, Object: artifacts.RuntimeObject{Digest: result.ArchiveDigest, Bytes: bytes}}, nil
}

type runtimeResolver struct{ images map[string]policy.Admission }

func (r runtimeResolver) Image(image string) (policy.Admission, error) {
	a, ok := r.images[image]
	if !ok {
		return a, policy.ErrAdmission
	}
	return a, nil
}
func (runtimeResolver) Volume(string, string) (string, error) { return "", policy.ErrAdmission }
func (runtimeResolver) Secret(string, string, string) error   { return policy.ErrAdmission }

// IssueRuntimeApproval records a concrete authorized decision. M12 supplies
// product approval decisions; this controlled issuer never approves implicitly.
func (s *Store) IssueRuntimeApproval(ctx context.Context, worker, incarnation string, generation int64, spec contracts.RuntimeSpecV2, until time.Time) error {
	now := time.Now()
	raw, err := json.Marshal(spec)
	if err != nil || len(raw) > contracts.MaxPlanBytes || !validIDs(worker, incarnation, spec.AppID, spec.DeploymentID) || generation < 1 || generation > runtimeagent.MaxGeneration || !until.After(now) || until.After(now.Add(time.Hour)) {
		return ErrInvalidInput
	}
	return s.write(ctx, func(c *sql.Conn) error {
		images := runtimeResolver{map[string]policy.Admission{}}
		for _, service := range spec.Services {
			i, err := runtimeImage(ctx, c, service.AdmissionID, service.Image)
			if err != nil || len(service.Volumes) != 0 || len(service.Secrets) != 0 {
				return ErrInvalidInput
			}
			images.images[service.Image] = i.Admission
		}
		if policy.ValidateRuntime(spec, images) != nil {
			return ErrInvalidInput
		}
		var n int
		if c.QueryRowContext(ctx, "SELECT count(*) FROM runtime_workers WHERE worker=? AND incarnation=? AND revoked=0 AND lease_until>?", worker, incarnation, now.UnixNano()).Scan(&n) != nil || n != 1 {
			return ErrConflict
		}
		var source string
		if c.QueryRowContext(ctx, `SELECT cl.result_json FROM deployments d JOIN applications a ON a.id=d.app_id JOIN clone_attempts cl ON cl.deployment_id=d.id AND cl.generation=d.generation AND cl.attempt=d.attempt WHERE d.id=? AND d.app_id=? AND d.generation=? AND a.deployment_generation=d.generation AND a.state='enabled' AND d.state IN ('SCANNING','APPROVED','DEPLOYING','HEALTH_CHECK','RUNNING') AND cl.outcome='success'`, spec.DeploymentID, spec.AppID, generation).Scan(&source) != nil {
			return ErrConflict
		}
		var clone contracts.CloneResult
		if json.Unmarshal([]byte(source), &clone) != nil || clone.SHA != spec.SHA || clone.ContextID != spec.ContextID || clone.Plan == nil || policy.PlanHash(*clone.Plan) != spec.PlanHash {
			return ErrConflict
		}
		var current int64
		err := c.QueryRowContext(ctx, "SELECT generation FROM runtime_fences WHERE app=?", spec.AppID).Scan(&current)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return runtimeDBError(ctx, err)
		}
		hash := policy.SpecHash(spec)
		if generation <= current {
			var w, inc, h string
			var expiry int64
			var revoked int
			if c.QueryRowContext(ctx, "SELECT worker,incarnation,spec_hash,expires_at,revoked FROM runtime_approvals WHERE app=? AND generation=?", spec.AppID, generation).Scan(&w, &inc, &h, &expiry, &revoked) == nil && generation == current && w == worker && inc == incarnation && h == hash && expiry == until.UnixNano() && revoked == 0 {
				return nil
			}
			return ErrConflict
		}
		if _, err = c.ExecContext(ctx, "INSERT INTO runtime_approvals VALUES(?,?,?,?,?,?,?,?,?,0)", spec.AppID, generation, worker, incarnation, spec.DeploymentID, hash, policy.Hash(), string(raw), until.UnixNano()); err != nil {
			return runtimeDBError(ctx, err)
		}
		_, err = c.ExecContext(ctx, "INSERT INTO runtime_fences VALUES(?,?) ON CONFLICT(app) DO UPDATE SET generation=excluded.generation", spec.AppID, generation)
		return runtimeDBError(ctx, err)
	})
}
func runtimeLease(ctx context.Context, c *sql.Conn, p artifacts.RuntimePeer, worker, incarnation string) (time.Time, error) {
	if !validIDs(worker, incarnation) || p.URI != "spiffe://tap/runtime-agent/"+worker || !contracts.ValidDigest("sha256:"+p.CertificateSHA256) {
		return time.Time{}, runtimeagent.ErrDenied
	}
	var lease, cert int64
	err := c.QueryRowContext(ctx, `SELECT w.lease_until,k.valid_until FROM runtime_workers w JOIN runtime_certificates k ON k.worker=w.worker AND k.incarnation=w.incarnation WHERE w.worker=? AND w.incarnation=? AND w.revoked=0 AND k.fingerprint=? AND k.revoked=0`, worker, incarnation, p.CertificateSHA256).Scan(&lease, &cert)
	now := time.Now()
	if err != nil || lease <= now.UnixNano() || cert <= now.UnixNano() {
		return time.Time{}, runtimeagent.ErrDenied
	}
	if cert < lease {
		lease = cert
	}
	return time.Unix(0, lease).UTC(), nil
}
func (s *Store) RuntimeLease(ctx context.Context, p artifacts.RuntimePeer, worker, incarnation string) (time.Time, error) {
	var until time.Time
	err := s.write(ctx, func(c *sql.Conn) error {
		var err error
		until, err = runtimeLease(ctx, c, p, worker, incarnation)
		return err
	})
	return until, err
}
func runtimeGrant(ctx context.Context, c *sql.Conn, p artifacts.RuntimePeer, command runtimeagent.Command) (runtimeauthority.Grant, error) {
	deny := func() (runtimeauthority.Grant, error) { return runtimeauthority.Grant{}, runtimeagent.ErrDenied }
	if command.Operation == "create" || command.Operation == "prepare" {
		var n int
		if c.QueryRowContext(ctx, "SELECT count(*) FROM runtime_queue WHERE command=? AND request_hash=? AND worker=? AND incarnation=? AND result_json IS NULL AND expires_at>?", command.ID, command.Hash(), command.WorkerID, command.Incarnation, time.Now().UnixNano()).Scan(&n) != nil || n != 1 {
			return deny()
		}
	}
	until, err := runtimeLease(ctx, c, p, command.WorkerID, command.Incarnation)
	if err != nil {
		return deny()
	}
	var raw, hash, ph string
	var expiry int64
	err = c.QueryRowContext(ctx, `SELECT a.spec_json,a.spec_hash,a.policy_hash,a.expires_at FROM runtime_approvals a JOIN runtime_fences f ON f.app=a.app AND f.generation=a.generation JOIN deployments d ON d.id=a.deployment AND d.app_id=a.app AND d.generation=a.generation JOIN applications ap ON ap.id=a.app AND ap.deployment_generation=a.generation AND ap.state='enabled' WHERE d.state IN ('SCANNING','APPROVED','DEPLOYING','HEALTH_CHECK','RUNNING') AND a.app=? AND a.generation=? AND a.worker=? AND a.incarnation=? AND a.deployment=? AND a.revoked=0`, command.AppID, command.Generation, command.WorkerID, command.Incarnation, command.DeploymentID).Scan(&raw, &hash, &ph, &expiry)
	if err != nil || hash != command.SpecHash || ph != command.PolicyHash || ph != policy.Hash() || expiry <= time.Now().UnixNano() {
		return deny()
	}
	var spec contracts.RuntimeSpecV2
	if json.Unmarshal([]byte(raw), &spec) != nil || policy.SpecHash(spec) != hash {
		return deny()
	}
	if time.Unix(0, expiry).Before(until) {
		until = time.Unix(0, expiry)
	}
	// Keep one second below the protocol's five-second ceiling so small
	// independent VM clock offsets do not turn a fresh grant into a false
	// future-expiry denial. The receiver's five-second bound stays strict.
	if until.After(time.Now().Add(4 * time.Second)) {
		until = time.Now().Add(4 * time.Second)
	}
	g := runtimeauthority.Grant{WorkerID: command.WorkerID, Incarnation: command.Incarnation, AppID: command.AppID, DeploymentID: command.DeploymentID, Generation: command.Generation, SpecHash: hash, PolicyHash: ph, SourceSHA: spec.SHA, ContextID: spec.ContextID, ExpiresAt: until.UTC()}
	seen := map[string]bool{}
	for _, service := range spec.Services {
		if seen[service.Image] {
			continue
		}
		i, err := runtimeImage(ctx, c, service.AdmissionID, service.Image)
		if err != nil {
			return deny()
		}
		g.Images = append(g.Images, i)
		seen[service.Image] = true
	}
	return g, nil
}
func (s *Store) RuntimeGrant(ctx context.Context, p artifacts.RuntimePeer, c runtimeagent.Command) (runtimeauthority.Grant, error) {
	var g runtimeauthority.Grant
	if c.Spec == nil || (c.Operation != "create" && c.Operation != "prepare") {
		return g, runtimeagent.ErrDenied
	}
	err := s.write(ctx, func(conn *sql.Conn) error {
		var err error
		g, err = runtimeGrant(ctx, conn, p, c)
		if err == nil && !g.Matches(time.Now(), c) {
			return runtimeagent.ErrDenied
		}
		return err
	})
	return g, err
}
func (s *Store) AuthorizeRuntime(ctx context.Context, p artifacts.RuntimePeer, q artifacts.RuntimeClaim) (artifacts.RuntimeObject, error) {
	var object artifacts.RuntimeObject
	c := runtimeagent.Command{WorkerID: q.WorkerID, Incarnation: q.Incarnation, AppID: q.AppID, DeploymentID: q.DeploymentID, Generation: q.Generation, SpecHash: q.SpecHash, PolicyHash: q.PolicyHash}
	err := s.write(ctx, func(conn *sql.Conn) error {
		g, err := runtimeGrant(ctx, conn, p, c)
		if err != nil {
			return err
		}
		for _, i := range g.Images {
			if i.Admission.ID == q.AdmissionID && i.Admission.Image == q.Image {
				object = i.Object
				return nil
			}
		}
		return runtimeagent.ErrDenied
	})
	return object, err
}
func (s *Store) RevokeRuntimeWorker(ctx context.Context, worker string) error {
	return s.revokeRuntime(ctx, "runtime_workers", "worker", worker)
}
func (s *Store) RevokeRuntimeCertificate(ctx context.Context, fingerprint string) error {
	return s.revokeRuntime(ctx, "runtime_certificates", "fingerprint", fingerprint)
}
func (s *Store) RevokeRuntimeImage(ctx context.Context, admission string) error {
	return s.revokeRuntime(ctx, "runtime_images", "admission", admission)
}
func (s *Store) RevokeRuntimeApproval(ctx context.Context, app string, generation int64) error {
	if !contracts.ValidJobID(app) || generation < 1 {
		return ErrInvalidInput
	}
	return s.write(ctx, func(c *sql.Conn) error {
		r, err := c.ExecContext(ctx, "UPDATE runtime_approvals SET revoked=1 WHERE app=? AND generation=? AND revoked=0", app, generation)
		if err != nil {
			return runtimeDBError(ctx, err)
		}
		n, err := r.RowsAffected()
		if err != nil || n != 1 {
			return ErrConflict
		}
		return nil
	})
}
func (s *Store) revokeRuntime(ctx context.Context, table, key, value string) error {
	if value == "" || len(value) > 128 || strings.ContainsAny(value, "\x00\r\n") {
		return ErrInvalidInput
	}
	// table/key are exclusively fixed constants from the four exported methods.
	return s.write(ctx, func(c *sql.Conn) error {
		r, err := c.ExecContext(ctx, "UPDATE "+table+" SET revoked=1 WHERE "+key+"=? AND revoked=0", value)
		if err != nil {
			return runtimeDBError(ctx, err)
		}
		n, err := r.RowsAffected()
		if err != nil || n != 1 {
			return ErrConflict
		}
		return nil
	})
}

func runtimeDBError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	return databaseError(ctx, err)
}

// QueueRuntimeCommand accepts only an already signed, independently validated
// command from trusted controller code; there is no public enqueue endpoint.
func (s *Store) QueueRuntimeCommand(ctx context.Context, c runtimeagent.Command, keys map[string]ed25519.PublicKey) error {
	if c.Validate(time.Now(), c.WorkerID, c.Incarnation, keys) != nil {
		return ErrInvalidInput
	}
	raw, err := json.Marshal(c)
	if err != nil || len(raw) > contracts.MaxPlanBytes {
		return ErrInvalidInput
	}
	expiry, _ := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	return s.write(ctx, func(conn *sql.Conn) error {
		var h string
		err := conn.QueryRowContext(ctx, "SELECT request_hash FROM runtime_queue WHERE command=?", c.ID).Scan(&h)
		if err == nil {
			if h == c.Hash() {
				return nil
			}
			return ErrConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return databaseError(ctx, err)
		}
		var total, worker int
		if conn.QueryRowContext(ctx, "SELECT count(*) FROM runtime_queue WHERE result_json IS NULL AND expires_at>?", time.Now().UnixNano()).Scan(&total) != nil || conn.QueryRowContext(ctx, "SELECT count(*) FROM runtime_queue WHERE worker=? AND result_json IS NULL AND expires_at>?", c.WorkerID, time.Now().UnixNano()).Scan(&worker) != nil {
			return ErrDatabase
		}
		if total >= 1024 || worker >= 64 {
			return ErrConflict
		}
		var n int
		if conn.QueryRowContext(ctx, "SELECT count(*) FROM runtime_workers WHERE worker=? AND incarnation=? AND revoked=0 AND lease_until>?", c.WorkerID, c.Incarnation, time.Now().UnixNano()).Scan(&n) != nil || n != 1 {
			return ErrConflict
		}
		// Explicit cleanup can still be queued after approval revocation. Creation and
		// image preparation must match the latest active approved generation.
		if c.Operation == "create" || c.Operation == "prepare" {
			if conn.QueryRowContext(ctx, `SELECT count(*) FROM runtime_approvals a JOIN runtime_fences f ON f.app=a.app AND f.generation=a.generation JOIN deployments d ON d.id=a.deployment AND d.app_id=a.app AND d.generation=a.generation JOIN applications ap ON ap.id=a.app AND ap.deployment_generation=a.generation AND ap.state='enabled' WHERE d.state IN ('SCANNING','APPROVED','DEPLOYING','HEALTH_CHECK','RUNNING') AND a.app=? AND a.generation=? AND a.worker=? AND a.incarnation=? AND a.deployment=? AND a.spec_hash=? AND a.policy_hash=? AND a.revoked=0 AND a.expires_at>?`, c.AppID, c.Generation, c.WorkerID, c.Incarnation, c.DeploymentID, c.SpecHash, c.PolicyHash, time.Now().UnixNano()).Scan(&n) != nil || n != 1 {
				return ErrConflict
			}
		}
		_, err = conn.ExecContext(ctx, "INSERT INTO runtime_queue(command,worker,incarnation,request_hash,command_json,expires_at,created_at) VALUES(?,?,?,?,?,?,?)", c.ID, c.WorkerID, c.Incarnation, c.Hash(), string(raw), expiry.UnixNano(), time.Now().UnixNano())
		return runtimeDBError(ctx, err)
	})
}
func boundedRuntimeResult(r runtimeagent.Result) bool {
	if !contracts.ValidJobID(r.CommandID) || (r.Code != "ok" && r.Code != "denied" && r.Code != "uncertain") || len(r.Logs) > runtimeagent.MaxLogs {
		return false
	}
	switch r.State {
	case "", "created", "running", "healthy", "stopped", "removed":
	default:
		return false
	}
	return true
}
func (s *Store) RuntimePoll(ctx context.Context, p artifacts.RuntimePeer, q runtimeauthority.PollRequest) (*runtimeagent.Command, error) {
	var next *runtimeagent.Command
	err := s.write(ctx, func(c *sql.Conn) error {
		if _, err := runtimeLease(ctx, c, p, q.WorkerID, q.Incarnation); err != nil {
			return err
		}
		if q.Result != nil {
			r := *q.Result
			if !boundedRuntimeResult(r) {
				return runtimeagent.ErrDenied
			}
			raw, err := json.Marshal(r)
			if err != nil || len(raw) > contracts.MaxPlanBytes {
				return runtimeagent.ErrDenied
			}
			var commandRaw string
			var old sql.NullString
			if c.QueryRowContext(ctx, "SELECT command_json,result_json FROM runtime_queue WHERE command=? AND worker=? AND incarnation=?", r.CommandID, q.WorkerID, q.Incarnation).Scan(&commandRaw, &old) != nil {
				return runtimeagent.ErrDenied
			}
			if old.Valid {
				if old.String != string(raw) {
					return runtimeagent.ErrConflict
				}
			} else {
				command, err := runtimeagent.Decode(strings.NewReader(commandRaw))
				if err != nil {
					return runtimeagent.ErrDenied
				}
				if r.Inventory != nil {
					if command.Operation != "probe" || r.Code != "ok" {
						return runtimeagent.ErrDenied
					}
					var key []byte
					var hash string
					if c.QueryRowContext(ctx, "SELECT inventory_key FROM runtime_workers WHERE worker=?", q.WorkerID).Scan(&key) != nil || c.QueryRowContext(ctx, "SELECT backend_hash FROM runtime_backends WHERE worker=? AND incarnation=? AND app=?", q.WorkerID, q.Incarnation, command.AppID).Scan(&hash) != nil || r.Inventory.VerifyFor(time.Now(), q.WorkerID, q.Incarnation, command.AppID, hash, command.Nonce, ed25519.PublicKey(key)) != nil {
						return runtimeagent.ErrDenied
					}
				} else if command.Operation == "probe" && r.Code == "ok" {
					return runtimeagent.ErrDenied
				}
				if _, err = c.ExecContext(ctx, "UPDATE runtime_queue SET result_json=? WHERE command=? AND result_json IS NULL", string(raw), r.CommandID); err != nil {
					return databaseError(ctx, err)
				}
			}
		}
		var raw string
		err := c.QueryRowContext(ctx, "SELECT command_json FROM runtime_queue WHERE worker=? AND incarnation=? AND result_json IS NULL AND expires_at>? ORDER BY created_at,command LIMIT 1", q.WorkerID, q.Incarnation, time.Now().UnixNano()).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return databaseError(ctx, err)
		}
		command, err := runtimeagent.Decode(strings.NewReader(raw))
		if err != nil {
			return runtimeagent.ErrDenied
		}
		next = &command
		return nil
	})
	return next, err
}

var _ runtimeauthority.State = (*Store)(nil)

// SetRuntimeScanPolicy is an explicit trusted policy update. Old admissions stop
// authorizing immediately when their immutable scan policy no longer matches.
func (s *Store) SetRuntimeScanPolicy(ctx context.Context, p contracts.BuildPolicy) error {
	if p.Validate(time.Now()) != nil {
		return ErrInvalidInput
	}
	return s.write(ctx, func(c *sql.Conn) error {
		var created int64
		err := c.QueryRowContext(ctx, "SELECT database_created_at FROM runtime_scan_policy WHERE singleton=1").Scan(&created)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return databaseError(ctx, err)
		}
		if created > p.DatabaseCreatedAt.UnixNano() {
			return ErrConflict
		}
		_, err = c.ExecContext(ctx, "INSERT INTO runtime_scan_policy VALUES(1,?,?) ON CONFLICT(singleton) DO UPDATE SET policy_hash=excluded.policy_hash,database_created_at=excluded.database_created_at", p.Hash(), p.DatabaseCreatedAt.UnixNano())
		return runtimeDBError(ctx, err)
	})
}

// RuntimeTargetGrant checks continuing execution of the exact original queued
// create and its signed finite restart allowance. It never grants a new create
// identity or resets a generation. The local supervisor must additionally hold
// the durable successful target/resource/restart records.
func (s *Store) RuntimeTargetGrant(ctx context.Context, p artifacts.RuntimePeer, q runtimeauthority.TargetRequest) (runtimeauthority.Grant, error) {
	var grant runtimeauthority.Grant
	if !validIDs(q.WorkerID, q.Incarnation, q.AppID, q.DeploymentID, q.OwnerID) || q.Generation < 1 || !contracts.ValidDigest(q.SpecHash) {
		return grant, runtimeagent.ErrDenied
	}
	err := s.write(ctx, func(conn *sql.Conn) error {
		var raw string
		if conn.QueryRowContext(ctx, "SELECT command_json FROM runtime_queue WHERE command=? AND worker=? AND incarnation=?", q.OwnerID, q.WorkerID, q.Incarnation).Scan(&raw) != nil {
			return runtimeagent.ErrDenied
		}
		original, err := runtimeagent.Decode(strings.NewReader(raw))
		if err != nil || original.Operation != "create" || original.Spec == nil || original.AppID != q.AppID || original.DeploymentID != q.DeploymentID || original.Generation != q.Generation || original.SpecHash != q.SpecHash {
			return runtimeagent.ErrDenied
		}
		request := original
		request.Operation = "" // continuing target, never new effects under its old command nonce
		grant, err = runtimeGrant(ctx, conn, p, request)
		if err != nil {
			return err
		}
		if !grant.Matches(time.Now(), original) {
			return runtimeagent.ErrDenied
		}
		grant.OwnerID = q.OwnerID
		return nil
	})
	return grant, err
}
