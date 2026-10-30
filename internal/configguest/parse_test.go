package configguest

import (
	"bytes"
	"context"
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/policy"
	composefixtures "dev-orchestrator/tests/fixtures/compose"
	dockerfilefixtures "dev-orchestrator/tests/fixtures/dockerfile"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const accepted = "services:\n  web:\n    build:\n      context: .\n      dockerfile: Dockerfile\n    expose: [\"8080\"]\n    depends_on: [db]\n  db:\n    image: registry.example.org/apps/db@" + digest + "\n"

func guest(t testing.TB) {
	t.Helper()
	if os.Getenv("M08_GUEST_TESTS") != "1" {
		t.Skip("repository parsers require disposable guest")
	}
	if _, e := os.Stat("/run/orchestrator-build-worker"); e != nil {
		t.Fatal("guest marker missing")
	}
}
func TestGuestComposeAccepted(t *testing.T) {
	guest(t)
	p, e := Compose([]byte(accepted))
	if e != nil || len(p.Services) != 2 || policy.ValidatePlan(p) != nil {
		t.Fatal("accepted subset", e)
	}
	p2, e := Compose([]byte("services:\n  web:\n    image: registry.example.org/apps/web@" + digest + "\n    command: [\"/app\", \"literal argument\"]\n    entrypoint: [\"/entry\"]\n    environment: {APP_MODE: \"production\"}\n    expose: [\"8080\"]\n    volumes: [{type: volume, source: data, target: /data}]\n    restart: on-failure:3\n    healthcheck: {test: [CMD, /probe], interval: 30s, timeout: 5s, retries: 3}\nvolumes: {data: {}}\n"))
	if e != nil || p2.Services[0].RestartAttempts != 3 {
		t.Fatal("full subset", e)
	}
}
func TestGuestComposeDenials(t *testing.T) {
	guest(t)
	cases := map[string]string{
		"duplicate": "services: {web: {image: a, image: b}}", "nested-duplicate": "services: {web: {environment: {X: a, X: b}}}", "alias": "services: {web: &x {image: a}, db: *x}", "anchor": "services: {web: &x {image: a}}", "merge": "services: {web: {<<: {image: a}}}", "tag": "services: !!map {}", "multiple": "services: {}\n---\nservices: {}", "key-type": "services: {true: {}}", "scalar-type": "services: {web: {image: true}}", "null": "services: {web: {image: null}}", "invalid-utf8": string([]byte{255}), "nul": "services: {}\x00", "interpolation": strings.Replace(accepted, "Dockerfile", "${CONFIG}", 1), "second-build": strings.Replace(accepted, "image: registry.example.org/apps/db@"+digest, "build: {context: ., dockerfile: Dockerfile}", 1), "tag-image": strings.Replace(accepted, digest, "latest", 1), "ambiguous": strings.Replace(accepted, "expose:", "image: registry.example.org/apps/web@"+digest+"\n    expose:", 1), "cycle": strings.Replace(accepted, "image: registry", "depends_on: [web]\n    image: registry", 1), "missing-dependency": strings.Replace(accepted, "[db]", "[absent]", 1), "shell-command": strings.Replace(accepted, "expose:", "command: echo unsafe\n    expose:", 1), "shell-health": strings.Replace(accepted, "expose:", "healthcheck: {test: [CMD-SHELL, echo unsafe], interval: 30s, timeout: 5s, retries: 3}\n    expose:", 1), "bind": strings.Replace(accepted, "expose:", "volumes: [{type: bind, source: /, target: /data}]\n    expose:", 1), "host-env": strings.Replace(accepted, "expose:", "environment: [HOME]\n    expose:", 1), "resource-overflow": strings.Replace(accepted, "expose:", "resources: {cpu_millis: 9223372036854775807}\n    expose:", 1), "depth": "services: " + strings.Repeat("[", 20) + "x" + strings.Repeat("]", 20), "size": strings.Repeat("x", contracts.MaxConfigurationBytes+1), "nodes": "services: {x: [" + strings.Repeat("a,", 10001) + "]}",
	}
	for _, key := range []string{"privileged", "devices", "device_cgroup_rules", "cap_add", "security_opt", "pid", "ipc", "uts", "userns_mode", "network_mode", "volumes_from", "container_name", "runtime", "extends", "profiles", "ports", "networks", "env_file", "configs", "secrets", "logging", "sysctls", "post_start", "pre_stop", "x-custom"} {
		cases[key] = strings.Replace(accepted, "expose:", key+": false\n    expose:", 1)
	}
	for _, key := range []string{"include", "networks", "name", "version", "x-custom"} {
		cases["top-"+key] = accepted + key + ": {}\n"
	}
	for n, data := range cases {
		t.Run(n, func(t *testing.T) {
			if _, e := Compose([]byte(data)); e == nil {
				t.Fatal("forbidden input accepted")
			}
			if strings.Contains(ErrDenied.Error(), "unsafe") {
				t.Fatal("diagnostic leakage")
			}
		})
	}
}
func TestGuestDockerfile(t *testing.T) {
	guest(t)
	for n, data := range map[string]string{"scratch": "# comment\nFROM scratch\nCOPY hello /hello\nUSER 1000\nCMD [\"/hello\"]\n", "multi": "FROM registry.example.org/apps/base@" + digest + " AS build\nRUN echo inert\nFROM scratch\nCOPY --from=build /out /app\nUSER 1000:1000\nENTRYPOINT [\"/app\"]\n"} {
		t.Run(n, func(t *testing.T) {
			if Dockerfile([]byte(data)) != nil {
				t.Fatal("valid Dockerfile denied")
			}
		})
	}
	for n, data := range map[string]string{"frontend-spaces": "# syntax = registry.example.org/frontend@" + digest + "\nFROM scratch", "frontend-tabs": "#\tSyNtAx\t=\tcustom/frontend\nFROM scratch", "frontend-bom": "\ufeff# syntax=custom/frontend\nFROM scratch", "frontend-json": "{\"syntax\":\"custom/frontend\"}\nFROM scratch", "frontend-c": "// syntax=custom/frontend\nFROM scratch", "frontend-shebang": "#!/bin/sh\n# syntax=custom/frontend\nFROM scratch", "remote-add": "FROM scratch\nADD https://example.org/x /x", "frontend": "# syntax=example.org/frontend\nFROM scratch", "escape": "# escape=`\nFROM scratch", "tag": "FROM alpine:latest", "ssh": "FROM scratch\nRUN --mount=type=ssh true", "network": "FROM scratch\nRUN --network=host true", "security": "FROM scratch\nRUN --security=insecure true", "device": "FROM scratch\nRUN --device=x true", "external-copy": "FROM scratch\nCOPY --from=registry.example.org/a /a /b", "arg": "ARG BASE\nFROM $BASE", "volume": "FROM scratch\nVOLUME /data", "onbuild": "FROM scratch\nONBUILD RUN true", "shell-entrypoint": "FROM scratch\nENTRYPOINT echo unsafe", "heredoc": "FROM scratch\nRUN <<EOF\ntrue\nEOF", "empty": "", "size": strings.Repeat("x", 65537)} {
		t.Run(n, func(t *testing.T) {
			if Dockerfile([]byte(data)) == nil {
				t.Fatal("unsafe Dockerfile accepted")
			}
		})
	}
}
func TestGuestRepositoryPaths(t *testing.T) {
	guest(t)
	d := t.TempDir()
	if os.WriteFile(filepath.Join(d, "Dockerfile"), []byte("FROM scratch\nUSER 1000\n"), 0600) != nil {
		t.Fatal("write")
	}
	if os.WriteFile(filepath.Join(d, "compose.yaml"), []byte(accepted), 0600) != nil {
		t.Fatal("write")
	}
	p, e := Repository(d, "compose", "compose.yaml")
	if e != nil || policy.PlanHash(p) == "" {
		t.Fatal(e)
	}
	first := policy.PlanHash(p)
	_ = os.WriteFile(filepath.Join(d, "Dockerfile"), []byte("FROM scratch\nUSER 1001\n"), 0600)
	p, e = Repository(d, "compose", "compose.yaml")
	if e != nil || first == policy.PlanHash(p) {
		t.Fatal("changed config not bound")
	}
	for _, name := range []string{"../Dockerfile", "/Dockerfile", ".git/config", "a/../Dockerfile"} {
		if _, e = Repository(d, "dockerfile", name); e == nil {
			t.Fatal("escape")
		}
	}
	_ = os.Symlink("Dockerfile", filepath.Join(d, "link"))
	if _, e = Repository(d, "dockerfile", "link"); e == nil {
		t.Fatal("symlink")
	}
	_ = os.Symlink("/etc", filepath.Join(d, "outside"))
	if _, e = Repository(d, "dockerfile", "outside/passwd"); e == nil {
		t.Fatal("ancestor symlink")
	}
}
func TestGuestServiceCount(t *testing.T) {
	guest(t)
	data := "services:\n"
	for i := 0; i < 6; i++ {
		data += "  s" + string(rune('a'+i)) + ":\n    image: registry.example.org/apps/x@" + digest + "\n    deploy: {resources: {limits: {cpus: \"0.1\", memory: 16M, pids: 16}}}\n"
		if i == 4 {
			if _, e := Compose([]byte(data)); e != nil {
				t.Fatal("five services denied", e)
			}
		}
	}
	if _, e := Compose([]byte(data)); e == nil {
		t.Fatal("six services accepted")
	}
}
func FuzzGuestCompose(f *testing.F) {
	guest(f)
	f.Add([]byte(accepted))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > contracts.MaxConfigurationBytes {
			return
		}
		p, e := Compose(b)
		if e == nil && policy.ValidatePlan(p) != nil {
			t.Fatal("invalid normalized output")
		}
	})
}
func FuzzGuestDockerfile(f *testing.F) {
	guest(f)
	f.Add([]byte("FROM scratch\nUSER 1000\n"))
	f.Fuzz(func(t *testing.T, b []byte) { _ = Dockerfile(b) })
}

func TestGuestParserBudgetAndDiagnostics(t *testing.T) {
	guest(t)
	d := t.TempDir()
	_ = os.WriteFile(filepath.Join(d, "Dockerfile"), []byte("FROM scratch\nUSER 1000\n"), 0600)
	p, e := Analyze(context.Background(), d, "dockerfile", "Dockerfile")
	if e != nil || policy.ValidatePlan(p) != nil {
		t.Fatal("isolated parser", e)
	}
	for file, want := range map[string]string{"memory.max": "134217728", "memory.swap.max": "0", "pids.max": "32", "cpu.max": "100000 100000"} {
		b, e := os.ReadFile("/sys/fs/cgroup/runner/config-parser/" + file)
		if e != nil || strings.TrimSpace(string(b)) != want {
			t.Fatal("parser budget", file)
		}
	}
	c, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, e = Analyze(c, d, "dockerfile", "Dockerfile"); e == nil || time.Since(start) > time.Second {
		t.Fatal("cancellation")
	}
	_ = os.WriteFile(filepath.Join(d, "secret.yaml"), []byte("services: {web: {privileged: SENTINEL_CONFIGURATION_SECRET}}"), 0600)
	if _, e = Analyze(context.Background(), d, "compose", "secret.yaml"); e == nil || strings.Contains(e.Error(), "SENTINEL") {
		t.Fatal("denial/diagnostic")
	}
	// The fixed child protocol must reject huge input with bounded output.
	cmd := exec.Command("/bin/clone-runner", "-normalize")
	cmd.Stdin = strings.NewReader(strings.Repeat("x", 9000))
	var out bytes.Buffer
	cmd.Stdout = &out
	if cmd.Run() == nil || out.Len() != 0 {
		t.Fatal("child protocol")
	}
}

func TestGuestRepositoryCorpus(t *testing.T) {
	guest(t)
	entries, _ := composefixtures.Files.ReadDir(".")
	for _, f := range entries {
		t.Run("compose-"+f.Name(), func(t *testing.T) {
			data, e := composefixtures.Files.ReadFile(f.Name())
			if e != nil {
				t.Fatal(e)
			}
			_, e = Compose(data)
			deny := strings.HasPrefix(f.Name(), "deny-")
			if (e != nil) != deny {
				t.Fatal("corpus outcome", e)
			}
		})
	}
	entries, _ = dockerfilefixtures.Files.ReadDir(".")
	for _, f := range entries {
		t.Run("dockerfile-"+f.Name(), func(t *testing.T) {
			data, e := dockerfilefixtures.Files.ReadFile(f.Name())
			if e != nil {
				t.Fatal(e)
			}
			e = Dockerfile(data)
			if (e != nil) != strings.HasPrefix(f.Name(), "deny-") {
				t.Fatal("corpus outcome", e)
			}
		})
	}
}

func TestGuestPathRace(t *testing.T) {
	guest(t)
	d := t.TempDir()
	outside := t.TempDir()
	inside := []byte("FROM scratch\nUSER 1000\n")
	_ = os.WriteFile(filepath.Join(d, "Dockerfile"), inside, 0600)
	_ = os.WriteFile(filepath.Join(outside, "Dockerfile"), []byte("FROM scratch\nUSER 1001\n"), 0600)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = os.Remove(filepath.Join(d, "Dockerfile"))
			_ = os.Symlink(filepath.Join(outside, "Dockerfile"), filepath.Join(d, "Dockerfile"))
			_ = os.WriteFile(filepath.Join(d, "replacement"), inside, 0600)
			_ = os.Rename(filepath.Join(d, "replacement"), filepath.Join(d, "Dockerfile"))
		}
	}()
	for i := 0; i < 200; i++ {
		p, e := Repository(d, "dockerfile", "Dockerfile")
		if e == nil && p.ConfigDigest != contracts.Digest(inside) {
			close(stop)
			<-done
			t.Fatal("racing symlink escaped root")
		}
	}
	close(stop)
	<-done
}

func TestGuestNestedComposeContext(t *testing.T) {
	guest(t)
	d := t.TempDir()
	_ = os.Mkdir(filepath.Join(d, "deploy"), 0700)
	_ = os.WriteFile(filepath.Join(d, "deploy", "compose.yaml"), []byte(accepted), 0600)
	_ = os.WriteFile(filepath.Join(d, "deploy", "Dockerfile"), []byte("FROM scratch\nUSER 1000\n"), 0600)
	p, e := Repository(d, "compose", "deploy/compose.yaml")
	if e != nil {
		t.Fatal(e)
	}
	selected, e := policy.BuildPath(p)
	if e != nil || selected != "deploy/Dockerfile" {
		t.Fatal("Compose context not relative to config directory", selected, e)
	}
}
