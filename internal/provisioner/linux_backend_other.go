//go:build !linux

package provisioner

import "context"

func newLinuxBackend(LinuxConfig) (Backend, error)           { return nil, ErrUnavailable }
func runLinuxGuest(context.Context, string, string) error    { return ErrUnavailable }
func expireLinuxGuest(context.Context, string, string) error { return ErrUnavailable }
func loadLinuxConfig(string) (LinuxConfig, error)            { return LinuxConfig{}, ErrUnavailable }
