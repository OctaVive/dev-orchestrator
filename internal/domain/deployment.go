// Package domain defines protocol-independent platform concepts.
package domain

// State describes a deployment attempt, not the application's entire lifecycle.
type State string

const (
	Submitted   State = "SUBMITTED"
	Validating  State = "VALIDATING"
	Cloning     State = "CLONING"
	Building    State = "BUILDING"
	Scanning    State = "SCANNING"
	Approved    State = "APPROVED"
	Deploying   State = "DEPLOYING"
	HealthCheck State = "HEALTH_CHECK"
	Running     State = "RUNNING"
	Failed      State = "FAILED"
	Cancelled   State = "CANCELLED"
	RolledBack  State = "ROLLED_BACK"
)

// CanTransition checks topology only. Health evidence, ownership, authorization,
// generation checks and durable audit/outbox writes remain controller duties.
func CanTransition(from, to State) bool {
	switch from {
	case Submitted:
		return to == Validating || to == Failed || to == Cancelled
	case Validating:
		return to == Cloning || to == Failed || to == Cancelled
	case Cloning:
		return to == Building || to == Failed || to == Cancelled
	case Building:
		return to == Scanning || to == Failed || to == Cancelled
	case Scanning:
		return to == Approved || to == Failed || to == Cancelled
	case Approved:
		return to == Deploying || to == Failed || to == Cancelled
	case Deploying:
		return to == HealthCheck || to == Failed || to == Cancelled
	case HealthCheck:
		return to == Running || to == Failed || to == Cancelled || to == RolledBack
	case Failed, Running:
		return to == RolledBack
	default:
		return false
	}
}
