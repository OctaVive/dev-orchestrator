package main

import (
	"dev-orchestrator/internal/runtimenet"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(1)
	}
	var err error
	switch os.Args[1] {
	case "--enter":
		err = runtimenet.Enter()
	case "--serve":
		err = runtimenet.Serve()
	default:
		os.Exit(1)
	}
	if err != nil {
		os.Stderr.WriteString("runtime_private_relay_denied\n")
		os.Exit(1)
	}
}
