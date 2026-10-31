package runtimeisolation

import (
	"io"
	"os"
	"strings"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/runtimeagent"
	"golang.org/x/sys/unix"
)

const AgentAnchorPath = "/var/lib/tap-runtime/agent.anchor"

type AgentEnrollment struct {
	Version     int    `json:"version"`
	WorkerID    string `json:"worker_id"`
	Incarnation string `json:"incarnation"`
	LedgerID    string `json:"ledger_id"`
}

func (e AgentEnrollment) Matches(l *runtimeagent.Ledger) bool {
	return e.Version == 1 && contracts.ValidJobID(e.LedgerID) && l != nil && l.Identity(e.WorkerID, e.Incarnation) && l.ID() == e.LedgerID
}
func ReadAgentEnrollment() (AgentEnrollment, error) {
	var e AgentEnrollment
	var st unix.Stat_t
	if unix.Lstat(AgentAnchorPath, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&0022 != 0 || st.Size > 4096 {
		return e, runtimeagent.ErrDenied
	}
	f, err := os.OpenFile(AgentAnchorPath, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return e, runtimeagent.ErrDenied
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return e, runtimeagent.ErrDenied
	}
	e, err = contracts.DecodeConfiguration[AgentEnrollment](strings.NewReader(string(raw)))
	if err != nil || e.Version != 1 || !contracts.ValidJobID(e.WorkerID) || !contracts.ValidJobID(e.Incarnation) || !contracts.ValidJobID(e.LedgerID) {
		return AgentEnrollment{}, runtimeagent.ErrDenied
	}
	return e, nil
}
