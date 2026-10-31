package runtimemeasure

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/policy"
	"dev-orchestrator/internal/runtimeagent"
	"dev-orchestrator/internal/runtimeengine"
	"dev-orchestrator/internal/runtimehost"
	"dev-orchestrator/internal/runtimeisolation"
	"dev-orchestrator/internal/runtimenet"
	"dev-orchestrator/internal/runtimeobservation"
	"golang.org/x/sys/unix"
)

type Server struct {
	relays  relayManager
	profile runtimehost.Profile
	active  chan struct{}
}
type peerKey struct{}

func New(p runtimehost.Profile) (*Server, error) {
	if os.Geteuid() != 0 || !p.Valid() || p.VerifyTools() != nil {
		return nil, runtimeagent.ErrUnsupported
	}
	return &Server{profile: p, active: make(chan struct{}, 2)}, nil
}
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	uid := uint32(^uint32(0))
	if u, ok := c.(*net.UnixConn); ok {
		if raw, err := u.SyscallConn(); err == nil {
			_ = raw.Control(func(fd uintptr) {
				if cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED); err == nil {
					uid = cred.Uid
				}
			})
		}
	}
	return context.WithValue(ctx, peerKey{}, uid)
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	deny := func() { http.Error(w, "denied", http.StatusForbidden) }
	if r.Context().Value(peerKey{}) != uint32(1000) || r.Method != "POST" || r.URL.Path != "/runtime/v1/measure" || r.URL.RawQuery != "" {
		deny()
		return
	}
	select {
	case s.active <- struct{}{}:
		defer func() { <-s.active }()
	default:
		deny()
		return
	}
	q, err := contracts.DecodeConfiguration[runtimeobservation.Request](http.MaxBytesReader(w, r.Body, 8192))
	if err != nil || !contracts.ValidJobID(q.AppID) {
		deny()
		return
	}
	var app *runtimehost.App
	for _, a := range s.profile.Apps {
		if a.ID == q.AppID {
			copy := a
			app = &copy
			break
		}
	}
	if app == nil {
		deny()
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	e, err := runtimeisolation.ReadEnrollment(q.AppID)
	if err != nil || e.WorkerID != s.profile.WorkerID || e.Incarnation != s.profile.Incarnation || e.Backend.Reservation() != app.Reservation() {
		deny()
		return
	}
	if q.Operation == "relay-stop" {
		if !contracts.ValidJobID(q.OwnerID) || q.ContainerID == "" || q.Port != 0 || q.Path != "" {
			deny()
			return
		}
		if s.relays.stop(q.AppID, q.OwnerID, q.ContainerID) != nil {
			deny()
			return
		}
		report := runtimeobservation.Report{Version: 1, WorkerID: e.WorkerID, Incarnation: e.Incarnation, AppID: q.AppID, BackendHash: e.Backend.Hash(), ProfileHash: s.profile.Hash(), ContainerID: q.ContainerID, Health: &runtimeobservation.Health{Status: 204}}
		raw, _ := json.Marshal(report)
		w.Header().Set("Content-Type", "application/json")
		w.Write(raw)
		return
	}
	live, err := runtimeisolation.CollectBackend(ctx, s.profile.WorkerID, s.profile.Incarnation, app.Reservation())
	if err != nil || live != e {
		deny()
		return
	}
	proof, err := backendProof(s.profile, *app, e)
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		deny()
		return
	}
	report := runtimeobservation.Report{Version: 1, WorkerID: e.WorkerID, Incarnation: e.Incarnation, AppID: q.AppID, BackendHash: e.Backend.Hash(), ProfileHash: s.profile.Hash(), Backend: proof}
	switch q.Operation {
	case "backend":
		if q.ContainerID != "" || q.OwnerID != "" || q.DeploymentID != "" || q.Generation != 0 || q.SpecHash != "" || q.Service != "" || q.UID != 0 || q.GID != 0 || q.Resources != (contracts.Resources{}) || q.Port != 0 || q.Path != "" {
			deny()
			return
		}
	case "container", "health", "relay-start", "relay-fetch":
		if (q.Operation == "container" && (q.Port != 0 || q.Path != "")) || ((q.Operation == "health" || q.Operation == "relay-start" || q.Operation == "relay-fetch") && (q.Port < 1 || q.Port > 65535 || len(q.Path) > 256 || !policy.ValidHealthURL(q.Path))) {
			deny()
			return
		}
		if !contracts.ValidJobID(q.OwnerID) || !contracts.ValidJobID(q.DeploymentID) || !contracts.ValidDigest(q.SpecHash) || q.Generation < 1 || q.Generation > runtimeagent.MaxGeneration || !policy.ValidName(q.Service) || q.UID < 1 || q.UID > 65535 || q.GID < 1 || q.GID > 65535 || q.Resources.MemoryBytes < 16<<20 || q.Resources.MemoryBytes > app.MemoryBytes || q.Resources.CPUMillis < 100 || q.Resources.CPUMillis > app.CPUMillis || q.Resources.PIDs < 16 || q.Resources.PIDs > app.PIDs || q.Resources.TmpBytes < 1 || q.Resources.WritableBytes < 1 || q.Resources.LogBytes < 1 {
			deny()
			return
		}
		client, err := runtimeengine.NewClient(e.Backend.Socket)
		if err != nil {
			deny()
			return
		}
		got, err := client.InspectContainer(ctx, q.ContainerID)
		client.Close()
		if err != nil || !got.State.Running || got.State.Pid <= 1 {
			deny()
			return
		}
		labels := map[string]string{"tap.worker": e.WorkerID, "tap.incarnation": e.Incarnation, "tap.app": q.AppID, "tap.deployment": q.DeploymentID, "tap.generation": strconv.FormatInt(q.Generation, 10), "tap.spec": q.SpecHash, "tap.owner": q.OwnerID, "tap.service": q.Service}
		if len(got.Config.Labels) != len(labels) {
			deny()
			return
		}
		for key, value := range labels {
			if got.Config.Labels[key] != value {
				deny()
				return
			}
		}
		processStart, startErr := processStartTicks(got.State.Pid)
		if startErr != nil {
			deny()
			return
		}
		// Independently require the live workload below the bounded app parent.
		group, groupErr := text("/proc/"+strconv.Itoa(got.State.Pid)+"/cgroup", 4096)
		if groupErr != nil || !strings.HasPrefix(group, "0::/") || !strings.Contains(group, "/"+app.Slice()+"/") {
			deny()
			return
		}
		observation, err := runtimeisolation.VerifyProcess(e, got.State.Pid, runtimeisolation.ProcessLimits{UID: q.UID, GID: q.GID, Resources: q.Resources})
		if err != nil {
			deny()
			return
		}
		afterStart, afterErr := processStartTicks(got.State.Pid)
		if afterErr != nil || afterStart != processStart {
			deny()
			return
		}
		report.ContainerID = q.ContainerID
		report.Process = &observation
		if q.Operation == "health" || q.Operation == "relay-start" || q.Operation == "relay-fetch" {
			netfd, err := unix.Open("/proc/"+strconv.Itoa(got.State.Pid)+"/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				deny()
				return
			}
			namespace := os.NewFile(uintptr(netfd), "network-namespace")
			defer namespace.Close()
			ns, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(netfd))
			if err != nil || ns != observation.NetworkNamespace || ns == proof.NetworkNamespace {
				deny()
				return
			}
			userfd, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(netfd), unix.NS_GET_USERNS, 0)
			if errno != 0 {
				deny()
				return
			}
			ownerNS, ownerErr := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(userfd)))
			unix.Close(int(userfd))
			if ownerErr != nil || ownerNS != e.Backend.UserNamespace {
				deny()
				return
			}
			if q.Operation == "relay-start" {
				if s.relays.start(namespace, q, observation.NetworkNamespace) != nil {
					deny()
					return
				}
			}
			if q.Operation == "relay-start" || q.Operation == "relay-fetch" {
				health, err := s.relays.fetch(ctx, q)
				if err != nil {
					deny()
					return
				}
				report.Health = &health
			} else {
				health, err := runtimenet.Probe(ctx, namespace, runtimenet.Configuration{Mode: "health", AppID: q.AppID, OwnerID: q.OwnerID, Port: q.Port, Path: q.Path, ExpiresAt: time.Now().Add(2 * time.Second)})
				if err != nil || health.Status != 200 {
					deny()
					return
				}
				report.Health = &runtimeobservation.Health{Status: health.Status, BodyBase64: health.BodyBase64, SHA256: health.SHA256}
			}
		}

	default:
		deny()
		return
	}
	raw, err := json.Marshal(report)
	if err != nil || len(raw) > 8192 {
		deny()
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(raw)
}

func processStartTicks(pid int) (uint64, error) {
	raw, err := runtimeisolation.ReadSmall("/proc/"+strconv.Itoa(pid)+"/stat", 16384)
	if err != nil {
		return 0, runtimeagent.ErrUnsupported
	}
	return runtimeisolation.StartTicks(raw)
}
