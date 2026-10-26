package contracts

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func validator(t *testing.T) *Validator {
	t.Helper()
	v, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../tests/fixtures/contracts/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mutate(t *testing.T, b []byte, change func(map[string]any)) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	change(doc)
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func commandContext() CommandContext {
	return CommandContext{
		WorkerID: "55555555-5555-4555-8555-555555555555",
		Now:      time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func TestDeploymentFixtures(t *testing.T) {
	v := validator(t)
	for _, name := range []string{"dockerfile-request", "compose-request"} {
		t.Run(name, func(t *testing.T) {
			request, err := v.DecodeDeployment(bytes.NewReader(fixture(t, name)))
			if err != nil {
				t.Fatal(err)
			}
			b, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := v.DecodeDeployment(bytes.NewReader(b)); err != nil {
				t.Fatalf("typed roundtrip: %v", err)
			}
		})
	}
}

func TestDeploymentRejectsMutations(t *testing.T) {
	v := validator(t)
	base := fixture(t, "dockerfile-request")
	cases := []struct {
		name string
		edit func(map[string]any)
	}{
		{"unknown-field", func(d map[string]any) { d["privileged"] = true }},
		{"wrong-case-field", func(d map[string]any) { d["App_ID"] = d["app_id"] }},
		{"missing-version", func(d map[string]any) { delete(d, "schema_version") }},
		{"unknown-version", func(d map[string]any) { d["schema_version"] = 2 }},
		{"missing-app", func(d map[string]any) { delete(d, "app_id") }},
		{"invalid-app", func(d map[string]any) { d["app_id"] = "app-1" }},
		{"unsupported-type", func(d map[string]any) { d["deployment_type"] = "shell" }},
		{"context-parent", func(d map[string]any) { d["build_context"] = "../source" }},
		{"context-absolute", func(d map[string]any) { d["build_context"] = "/source" }},
		{"context-windows", func(d map[string]any) { d["build_context"] = `C:\source` }},
		{"context-dot-segment", func(d map[string]any) { d["build_context"] = "src/./app" }},
		{"git-metadata", func(d map[string]any) { d["config_path"] = ".git/config" }},
		{"config-root", func(d map[string]any) { d["config_path"] = "." }},
		{"null-env", func(d map[string]any) { d["environment"] = nil }},
		{"reserved-env", func(d map[string]any) { d["environment"] = map[string]any{"DOCKER_HOST": "tcp://internal"} }},
		{"nul-env", func(d map[string]any) { d["environment"] = map[string]any{"APP": "x\x00y"} }},
		{"env-object", func(d map[string]any) { d["environment"] = map[string]any{"APP": map[string]any{"value": "x"}} }},
		{"env-too-long", func(d map[string]any) { d["environment"] = map[string]any{"APP": strings.Repeat("a", 4097)} }},
		{"host-mount", func(d map[string]any) {
			d["volumes"] = []any{map[string]any{"source": "/var/run/docker.sock", "target": "/data", "read_only": true}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := mutate(t, base, tc.edit)
			if _, err := v.DecodeDeployment(bytes.NewReader(b)); err == nil {
				t.Fatal("unsafe request accepted")
			}
		})
	}
}

func TestRepositoryURLAndBranchBoundary(t *testing.T) {
	v := validator(t)
	base := fixture(t, "dockerfile-request")
	badURLs := []string{
		"http://github.com/example/repo", "file:///etc/passwd", "ext::sh -c id",
		"git@github.com:example/repo.git", "ssh://git@github.com/example/repo",
		"https://token@github.com/example/repo", "https://127.0.0.1/repo", "https://[::1]/repo",
		"https://169.254.169.254/latest/meta-data", "https://host.internal/repo",
		"https://localhost/repo", "https://github.com:8443/repo", "https://github.com/repo#fragment",
		"https://github.com/repo?redirect=internal", "https://github.com/%2e%2e/repo",
		"https://github.com/../repo", "https://github.com./repo", "https://github.com/",
	}
	for _, raw := range badURLs {
		t.Run(raw, func(t *testing.T) {
			b := mutate(t, base, func(d map[string]any) { d["repository_url"] = raw })
			if _, err := v.DecodeDeployment(bytes.NewReader(b)); err == nil {
				t.Fatal("unsafe URL shape accepted")
			}
		})
	}
	for _, branch := range []string{"", "-upload-pack=evil", "main; id", "a..b", "a@{b", "a.lock", "a//b", ".hidden", "a/", "a\\b", "refs/heads/main", "main\n"} {
		t.Run("branch-"+branch, func(t *testing.T) {
			b := mutate(t, base, func(d map[string]any) { d["branch"] = branch })
			if _, err := v.DecodeDeployment(bytes.NewReader(b)); err == nil {
				t.Fatal("unsafe branch accepted")
			}
		})
	}
}

func TestUnambiguousBoundedJSON(t *testing.T) {
	v := validator(t)
	base := fixture(t, "dockerfile-request")
	cases := [][]byte{
		[]byte(`{"schema_version":1,"schema_version":1}`),
		[]byte(`{"app_id":"one","app_\u0069d":"two"}`),
		[]byte(`{"environment":{"APP":"one","APP":"two"}}`),
		[]byte(`{"unknown":[{"x":1,"x":2}]}`),
		[]byte(`{"x":` + strings.Repeat("[", 40) + "0" + strings.Repeat("]", 40) + "}"),
		[]byte(`{"x":` + strings.Repeat(`{"x":`, 40) + "0" + strings.Repeat("}", 40) + "}"),
		append(append([]byte{}, base...), []byte(" {}")...),
		[]byte("[]"), []byte("null"), []byte(""), []byte(`{"x":`),
		[]byte(`{"schema_version":1e1000000000}`),
		[]byte(`{"schema_version":9999999999999999999999999999999}`),
		[]byte(`{"schema_version":1.0}`),
		[]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'},
	}
	for i, b := range cases {
		if _, err := v.DecodeDeployment(bytes.NewReader(b)); !errors.Is(err, ErrMalformedJSON) {
			t.Errorf("case %d: expected malformed JSON, got %v", i, err)
		}
	}
	if _, err := v.DecodeDeployment(strings.NewReader(strings.Repeat(" ", MaxDeploymentBytes+1))); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("expected size rejection, got %v", err)
	}
}

func TestAgentFixtureAndTypedRoundtrip(t *testing.T) {
	v := validator(t)
	command, err := v.DecodeAgentCommand(bytes.NewReader(fixture(t, "agent-command")), commandContext())
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.DecodeAgentCommand(bytes.NewReader(b), commandContext()); err != nil {
		t.Fatal(err)
	}
}

func TestAgentRejectsMutations(t *testing.T) {
	v := validator(t)
	base := fixture(t, "agent-command")
	cases := []struct {
		name string
		edit func(map[string]any)
	}{
		{"unknown-envelope", func(d map[string]any) { d["shell"] = "id" }},
		{"wrong-action", func(d map[string]any) { d["action"] = "exec" }},
		{"unsigned", func(d map[string]any) { delete(d, "signature") }},
		{"invalid-signature", func(d map[string]any) { d["signature"] = "not-a-signature" }},
		{"invalid-date", func(d map[string]any) { d["expires_at"] = "tomorrow" }},
		{"expired", func(d map[string]any) { d["expires_at"] = "2030-01-01T00:00:00Z" }},
		{"too-long-lease", func(d map[string]any) { d["expires_at"] = "2030-01-01T01:00:00Z" }},
		{"wrong-worker", func(d map[string]any) { d["worker_id"] = d["app_id"] }},
		{"zero-generation", func(d map[string]any) { d["generation"] = 0 }},
		{"fractional-generation", func(d map[string]any) { d["generation"] = 1.5 }},
		{"excess-generation", func(d map[string]any) { d["generation"] = 9007199254740992.0 }},
		{"unknown-spec", func(d map[string]any) { spec(d)["docker_socket"] = true }},
		{"unsafe-profile", func(d map[string]any) { spec(d)["profile"] = "privileged" }},
		{"no-services", func(d map[string]any) { spec(d)["services"] = []any{} }},
		{"too-many-services", func(d map[string]any) {
			spec(d)["services"] = []any{service(d), service(d), service(d), service(d), service(d), service(d)}
		}},
		{"duplicate-service", func(d map[string]any) { spec(d)["services"] = []any{service(d), service(d)} }},
		{"root", func(d map[string]any) { service(d)["uid"] = 0 }},
		{"privileged", func(d map[string]any) { service(d)["privileged"] = true }},
		{"host-network", func(d map[string]any) { service(d)["network_mode"] = "host" }},
		{"host-ports", func(d map[string]any) { service(d)["ports"] = []any{8080} }},
		{"capabilities", func(d map[string]any) { service(d)["cap_add"] = []any{"SYS_ADMIN"} }},
		{"unconfined", func(d map[string]any) { service(d)["security_opt"] = []any{"seccomp=unconfined"} }},
		{"mutable-image", func(d map[string]any) { service(d)["image"] = "nginx:latest" }},
		{"shell-command-string", func(d map[string]any) { service(d)["command"] = "sh -c id" }},
		{"unlimited-memory", func(d map[string]any) { service(d)["resources"].(map[string]any)["memory_bytes"] = 0 }},
		{"missing-limits", func(d map[string]any) { delete(service(d), "resources") }},
		{"wrong-ingress", func(d map[string]any) { spec(d)["ingress"].(map[string]any)["service"] = "missing" }},
		{"health-ssrf", func(d map[string]any) { spec(d)["ingress"].(map[string]any)["health_path"] = "https://internal/" }},
		{"reserved-env", func(d map[string]any) { service(d)["environment"] = map[string]any{"ORCH_KEY": "x"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := v.DecodeAgentCommand(bytes.NewReader(mutate(t, base, tc.edit)), commandContext()); err == nil {
				t.Fatal("unsafe command accepted")
			}
		})
	}
}

func spec(d map[string]any) map[string]any { return d["spec"].(map[string]any) }
func service(d map[string]any) map[string]any {
	return spec(d)["services"].([]any)[0].(map[string]any)
}

func TestAgentRequiresTrustedContext(t *testing.T) {
	v := validator(t)
	b := fixture(t, "agent-command")
	cases := []CommandContext{
		{}, {WorkerID: commandContext().WorkerID},
		{WorkerID: commandContext().WorkerID, Now: commandContext().Now, LastGeneration: 1},
		{WorkerID: commandContext().WorkerID, Now: commandContext().Now, LastGeneration: -1},
	}
	for _, ctx := range cases {
		if _, err := v.DecodeAgentCommand(bytes.NewReader(b), ctx); !errors.Is(err, ErrCommandContext) {
			t.Errorf("expected context rejection, got %v", err)
		}
	}
	if _, err := v.DecodeAgentCommand(strings.NewReader(strings.Repeat(" ", MaxCommandBytes+1)), commandContext()); !errors.Is(err, ErrTooLarge) {
		t.Fatal("oversized command accepted")
	}
}

func TestMountIsolationShape(t *testing.T) {
	v := validator(t)
	base := fixture(t, "compose-request")
	for _, target := range []string{"/", "/etc", "/proc", "/data/../etc", "/data//x", "/data/"} {
		b := mutate(t, base, func(d map[string]any) { d["volumes"].([]any)[0].(map[string]any)["target"] = target })
		if _, err := v.DecodeDeployment(bytes.NewReader(b)); err == nil {
			t.Errorf("unsafe target %q accepted", target)
		}
	}
	for _, target := range []string{"/data", "/data/cache"} {
		b := mutate(t, base, func(d map[string]any) {
			mount := d["volumes"].([]any)[0]
			d["volumes"] = []any{mount, map[string]any{
				"volume_id": "66666666-6666-4666-8666-666666666666", "target": target, "read_only": false,
			}}
		})
		if _, err := v.DecodeDeployment(bytes.NewReader(b)); err == nil {
			t.Errorf("overlapping target %q accepted", target)
		}
	}
}

func TestErrorsDoNotEchoSensitiveInput(t *testing.T) {
	v := validator(t)
	secret := "fixture-secret-not-for-logs"
	b := mutate(t, fixture(t, "dockerfile-request"), func(d map[string]any) {
		d["environment"] = map[string]any{"APP": map[string]any{"password": secret}}
	})
	_, err := v.DecodeDeployment(bytes.NewReader(b))
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("validation error leaked input or accepted invalid body")
	}
}

func TestStrictCredentials(t *testing.T) {
	v := validator(t)
	valid := `{"username":"Admin","password":"fixture-password-only"}`
	credentials, err := v.DecodeCredentials(strings.NewReader(valid))
	if err != nil || credentials.Username != "Admin" || credentials.Password != "fixture-password-only" {
		t.Fatal("valid credentials rejected", err)
	}
	for _, body := range []string{
		`{"username":"admin","password":"x","role":"admin"}`,
		`{"Username":"admin","password":"x"}`,
		`{"username":"admin","password":null}`,
		`{"username":"admin","password":"one","password":"two"}`,
		`{"username":"admin","password":"x\u0000y"}`,
		`{"username":"admin","password":"` + strings.Repeat("x", 1025) + `"}`,
		valid + ` {}`,
	} {
		if _, err := v.DecodeCredentials(strings.NewReader(body)); err == nil {
			t.Fatal("unsafe credentials accepted")
		}
	}
	if _, err := v.DecodeCredentials(strings.NewReader(strings.Repeat(" ", MaxCredentialsBytes+1))); !errors.Is(err, ErrTooLarge) {
		t.Fatal("oversized credentials accepted")
	}
}

func FuzzCredentialsDecode(f *testing.F) {
	v, err := NewValidator()
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(`{"username":"admin","password":"fixture-password-only"}`))
	f.Add([]byte(`{"username":"one","username":"two"}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = v.DecodeCredentials(bytes.NewReader(b)) })
}

func FuzzDeploymentDecode(f *testing.F) {
	v, err := NewValidator()
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(`{"schema_version":1}`))
	f.Add([]byte(`{"x":1,"x":2}`))
	seed, err := os.ReadFile("../../tests/fixtures/contracts/dockerfile-request.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = v.DecodeDeployment(bytes.NewReader(b))
	})
}

func FuzzAgentDecode(f *testing.F) {
	v, err := NewValidator()
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(`{"schema_version":1}`))
	f.Add([]byte(`{"spec":{"services":[{"uid":0}]}}`))
	seed, err := os.ReadFile("../../tests/fixtures/contracts/agent-command.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = v.DecodeAgentCommand(bytes.NewReader(b), commandContext())
	})
}

func TestAgentRejectsUnknownFieldsAtEveryStructuredLevel(t *testing.T) {
	v := validator(t)
	base := fixture(t, "agent-command")
	for _, level := range []string{"envelope", "spec", "service", "resources", "ingress", "mount"} {
		t.Run(level, func(t *testing.T) {
			b := mutate(t, base, func(d map[string]any) {
				var object map[string]any
				switch level {
				case "envelope":
					object = d
				case "spec":
					object = spec(d)
				case "service":
					object = service(d)
				case "resources":
					object = service(d)["resources"].(map[string]any)
				case "ingress":
					object = spec(d)["ingress"].(map[string]any)
				case "mount":
					object = map[string]any{"volume_id": d["app_id"], "target": "/data", "read_only": false}
					service(d)["volumes"] = []any{object}
				}
				object["unexpected"] = true
			})
			if _, err := v.DecodeAgentCommand(bytes.NewReader(b), commandContext()); err == nil {
				t.Fatal("unknown field accepted")
			}
		})
	}
}

func TestAgentAcceptsBoundedMultiServiceSpec(t *testing.T) {
	v := validator(t)
	b := mutate(t, fixture(t, "agent-command"), func(d map[string]any) {
		first := service(d)
		second := make(map[string]any)
		for k, value := range first {
			second[k] = value
		}
		second["name"] = "database"
		spec(d)["services"] = []any{first, second}
	})
	command, err := v.DecodeAgentCommand(bytes.NewReader(b), commandContext())
	if err != nil || len(command.Spec.Services) != 2 {
		t.Fatalf("bounded multi-service spec rejected: %v", err)
	}
}
