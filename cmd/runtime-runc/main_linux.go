// runtime-runc is a fixed platform runtime inside the runtime VM, not an agent
// endpoint. It supplements engine-generated OCI bundles and execs pinned runc.
package main

import (
	"dev-orchestrator/internal/runtimeprofile"
	"os"
	"strings"
	"syscall"
)

func main() {
	args := os.Args[1:]
	bundle := ""
	create := false
	for i, a := range args {
		if a == "create" || a == "run" {
			create = true
		}
		if a == "--bundle" || a == "-b" {
			if i+1 >= len(args) {
				os.Exit(1)
			}
			bundle = args[i+1]
		}
		if strings.HasPrefix(a, "--bundle=") {
			bundle = strings.TrimPrefix(a, "--bundle=")
		}
	}
	if create {
		if bundle == "" {
			bundle, _ = os.Getwd()
		}
		app := os.Getenv("TAP_RUNTIME_APP")
		var err error
		if app == "" {
			err = runtimeprofile.Harden(bundle)
		} else {
			err = runtimeprofile.HardenApp(bundle, app)
		}
		if err != nil {
			os.Stderr.WriteString("runtime_bundle_denied\n")
			os.Exit(1)
		}
	}
	if syscall.Exec("/usr/local/libexec/runc-real", append([]string{"runc"}, args...), os.Environ()) != nil {
		os.Stderr.WriteString("runtime_exec_denied\n")
		os.Exit(1)
	}
}
