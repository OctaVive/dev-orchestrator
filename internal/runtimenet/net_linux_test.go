package runtimenet

import (
	"context"
	"testing"
	"time"
)

func TestFixedRelayConfigurationRejectsSelectors(t *testing.T) {
	base := Configuration{Mode: "relay", AppID: "11111111-1111-4111-8111-111111111111", OwnerID: "22222222-2222-4222-8222-222222222222", Port: 8080, Path: "/health", ExpiresAt: time.Now().Add(30 * time.Second)}
	if !base.Valid() {
		t.Fatal("bounded fixture rejected")
	}
	for _, field := range []string{"mode", "app", "owner", "port", "absolute-url", "network-path", "expired", "unbounded"} {
		t.Run(field, func(t *testing.T) {
			c := base
			switch field {
			case "mode":
				c.Mode = "exec"
			case "app":
				c.AppID = "../../proc/1/ns/net"
			case "owner":
				c.OwnerID = "/var/run/docker.sock"
			case "port":
				c.Port = 65536
			case "absolute-url":
				c.Path = "http://169.254.169.254/"
			case "network-path":
				c.Path = "//169.254.169.254/"
			case "expired":
				c.ExpiresAt = time.Now().Add(-time.Second)
			case "unbounded":
				c.ExpiresAt = time.Now().Add(2 * time.Minute)
			}
			if c.Valid() {
				t.Fatal("unsafe relay configuration admitted")
			}
		})
	}
	if _, err := Start(context.Background(), nil, base); err == nil {
		t.Fatal("missing checked namespace admitted")
	}
}
