package policy

// Controls is trusted adapter output, never repository/agent command input.
// M09 must enforce every item and inspect the resulting engine state.
type Controls struct {
	Rootless, NonRoot, DropAllCapabilities, NoNewPrivileges             bool
	ReadOnlyRoot, PrivateNamespaces, Seccomp, MAC                       bool
	NoHostPorts, AppPrivateNetwork, DenyExternalAndCrossApp             bool
	BoundedCPU, BoundedMemory, BoundedPIDs, BoundedStorage, BoundedLogs bool
	FiniteRestartAndHealth                                              bool
}

func RequiredControls() Controls {
	return Controls{true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true}
}
