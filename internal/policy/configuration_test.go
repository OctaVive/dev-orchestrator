package policy_test

import (
	"bytes"
	"dev-orchestrator/internal/agentpolicy"
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/policy"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const id = "11111111-1111-4111-8111-111111111111"
const image = "registry.example.org/apps/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type resolver struct{ bad string }

func (r resolver) Image(s string) (policy.Admission, error) {
	if r.bad == "missing" {
		return policy.Admission{}, errors.New("missing")
	}
	a := policy.Admission{ID: "admitted", Image: s, PolicyHash: policy.Hash(), Platform: "linux/amd64", User: "1000:1000", Environment: map[string]string{"BASE": "value"}}
	switch r.bad {
	case "platform":
		a.Platform = "linux/arm64"
	case "policy":
		a.PolicyHash = "stale"
	case "root":
		a.User = "0"
	case "named":
		a.User = "app"
	case "gid":
		a.User = "1000:0"
	case "volume":
		a.Volumes = []string{"/data"}
	case "digest":
		a.Image = "wrong"
	}
	return a, nil
}
func (r resolver) Volume(app, n string) (string, error) {
	if r.bad == "ownership" || app != id {
		return "", errors.New("wrong app")
	}
	return id, nil
}
func (r resolver) Secret(app, n, v string) error {
	if r.bad == "ownership" {
		return errors.New("wrong app")
	}
	return nil
}
func plan() contracts.ConfigurationPlan {
	return contracts.ConfigurationPlan{Version: 1, PolicyHash: policy.Hash(), ConfigDigest: contracts.Digest([]byte("config")), Services: []contracts.PlannedService{{Name: "web", Image: image, Resources: policy.Defaults(), Expose: []int{8080}, Environment: map[string]string{"APP_MODE": "production"}}}}
}
func ctx() policy.Context {
	return policy.Context{AppID: id, DeploymentID: id, SHA: strings.Repeat("a", 40), ContextID: strings.Repeat("b", 64), Ingress: contracts.Ingress{Service: "web", Port: 8080, HealthPath: "/health"}}
}
func TestNormalizationAndCanonicalIdentity(t *testing.T) {
	p := plan()
	s, e := policy.Finalize(p, ctx(), resolver{})
	if e != nil || policy.ValidateRuntime(s, resolver{}) != nil {
		t.Fatal(e)
	}
	if s.Services[0].Environment["BASE"] != "value" || s.Services[0].Environment["APP_MODE"] != "production" {
		t.Fatal("environment semantics")
	}
	p2 := plan()
	p2.Services[0].Environment = map[string]string{"Z": "last", "A": "first"}
	p.Services[0].Environment = map[string]string{"A": "first", "Z": "last"}
	if policy.PlanHash(p) != policy.PlanHash(p2) {
		t.Fatal("map ordering")
	}
	p2.Services[0].Command = []string{"a", "b"}
	p.Services[0].Command = []string{"b", "a"}
	if policy.PlanHash(p) == policy.PlanHash(p2) {
		t.Fatal("argv order lost")
	}
	if policy.PlanHash(plan()) != "sha256:c84abf5068131fe5a27e1f714013cd1e18b3665baecff52c494473411b9e1cd0" {
		t.Fatal("canonical golden changed", policy.PlanHash(plan()))
	}
}
func TestPlanSemanticDenials(t *testing.T) {
	cases := map[string]func(*contracts.ConfigurationPlan){"version": func(p *contracts.ConfigurationPlan) { p.Version = 3 }, "policy": func(p *contracts.ConfigurationPlan) { p.PolicyHash = "stale" }, "duplicate": func(p *contracts.ConfigurationPlan) { p.Services = append(p.Services, p.Services[0]) }, "root-key": func(p *contracts.ConfigurationPlan) { p.Services[0].Name = "../unsafe" }, "tag": func(p *contracts.ConfigurationPlan) { p.Services[0].Image = "image:latest" }, "reserved-env": func(p *contracts.ConfigurationPlan) { p.Services[0].Environment["DOCKER_HOST"] = "x" }, "command-empty": func(p *contracts.ConfigurationPlan) { p.Services[0].Command = []string{} }, "command-nul": func(p *contracts.ConfigurationPlan) { p.Services[0].Command = []string{"x\x00"} }, "resource": func(p *contracts.ConfigurationPlan) { p.Services[0].Resources.CPUMillis = 2147483647 }, "missing-dependency": func(p *contracts.ConfigurationPlan) { p.Services[0].DependsOn = []string{"absent"} }, "self-dependency": func(p *contracts.ConfigurationPlan) { p.Services[0].DependsOn = []string{"web"} }, "health": func(p *contracts.ConfigurationPlan) {
		p.Services[0].Health = &contracts.Healthcheck{Argv: []string{"/probe"}, IntervalSeconds: 1, TimeoutSeconds: 30, Retries: 1}
	}, "restart": func(p *contracts.ConfigurationPlan) { p.Services[0].RestartAttempts = 4 }, "port": func(p *contracts.ConfigurationPlan) { p.Services[0].Expose = []int{8080, 8080} }, "mount": func(p *contracts.ConfigurationPlan) {
		p.Services[0].Mounts = []contracts.PlannedMount{{Name: "data", Target: "/var/run/docker.sock"}}
	}, "overlap": func(p *contracts.ConfigurationPlan) {
		p.Services[0].Mounts = []contracts.PlannedMount{{Name: "one", Target: "/data"}, {Name: "two", Target: "/data/sub"}}
	}, "output-limit": func(p *contracts.ConfigurationPlan) {
		for i := 0; i < 32; i++ {
			p.Services[0].Environment["KEY"+strings.Repeat("X", i)] = strings.Repeat("x", 4096)
		}
	}}
	for n, f := range cases {
		t.Run(n, func(t *testing.T) {
			p := plan()
			f(&p)
			if policy.ValidatePlan(p) == nil {
				t.Fatal("accepted")
			}
		})
	}
}
func TestFinalizationAdmissionAndOwnership(t *testing.T) {
	for _, bad := range []string{"missing", "platform", "policy", "root", "named", "gid", "volume", "digest", "ownership"} {
		t.Run(bad, func(t *testing.T) {
			p := plan()
			p.Services[0].Mounts = []contracts.PlannedMount{{Name: "data", Target: "/data"}}
			if _, e := policy.Finalize(p, ctx(), resolver{bad}); e == nil {
				t.Fatal("untrusted artifact/ownership accepted")
			}
		})
	}
	for _, user := range []string{"0", "root", "1000:0", "1000:root", "65536", "1000:1000:1000", "99999999999999999999"} {
		if _, _, e := policy.User(user); e == nil {
			t.Fatal("unsafe user", user)
		}
	}
	p := plan()
	p.Services[0].Mounts = []contracts.PlannedMount{{Name: "data", Target: "/data"}}
	if _, e := policy.Finalize(p, ctx(), resolver{}); e != nil {
		t.Fatal("owned volume", e)
	}
}
func command(t *testing.T) contracts.AgentCommandV2 {
	t.Helper()
	s, e := policy.Finalize(plan(), ctx(), resolver{})
	if e != nil {
		t.Fatal(e)
	}
	return contracts.AgentCommandV2{SchemaVersion: 2, CommandID: id, WorkerID: id, Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano), Nonce: strings.Repeat("b", 64), KeyID: "controller", Signature: base64.StdEncoding.EncodeToString(make([]byte, 64)), Spec: s, SpecHash: policy.SpecHash(s)}
}
func agentContext() agentpolicy.Context {
	return agentpolicy.Context{WorkerID: id, Now: time.Now(), Resolver: resolver{}}
}
func TestIndependentAgentPolicy(t *testing.T) {
	a := command(t)
	b, _ := json.Marshal(a)
	if _, e := agentpolicy.Decode(bytes.NewReader(b), agentContext()); e != nil {
		t.Fatal(e)
	}
	cases := map[string]func(*contracts.AgentCommandV2){"version": func(a *contracts.AgentCommandV2) { a.SchemaVersion = 1 }, "worker": func(a *contracts.AgentCommandV2) { a.WorkerID = "wrong" }, "expiry": func(a *contracts.AgentCommandV2) { a.ExpiresAt = time.Now().Add(-time.Second).Format(time.RFC3339Nano) }, "generation": func(a *contracts.AgentCommandV2) { a.Generation = 0 }, "hash": func(a *contracts.AgentCommandV2) { a.SpecHash = contracts.Digest(nil) }, "signature-shape": func(a *contracts.AgentCommandV2) { a.Signature = "invalid" }, "root": func(a *contracts.AgentCommandV2) { a.Spec.Services[0].UID = 0 }, "policy": func(a *contracts.AgentCommandV2) { a.Spec.PolicyHash = "stale" }, "ingress": func(a *contracts.AgentCommandV2) { a.Spec.Ingress.Service = "absent" }, "health-url": func(a *contracts.AgentCommandV2) { a.Spec.Ingress.HealthPath = "https://169.254.169.254/" }, "secret": func(a *contracts.AgentCommandV2) {
		a.Spec.Services[0].Secrets = []contracts.SecretReference{{ID: id, Version: contracts.Digest(nil), Target: "/etc/passwd"}}
	}}
	for n, f := range cases {
		t.Run(n, func(t *testing.T) {
			a := command(t)
			f(&a)
			if n != "hash" {
				a.SpecHash = policy.SpecHash(a.Spec)
			}
			b, _ := json.Marshal(a)
			if _, e := agentpolicy.Decode(bytes.NewReader(b), agentContext()); e == nil {
				t.Fatal("forged command accepted")
			}
		})
	}
	for _, key := range []string{"privileged", "ports", "devices", "network_mode", "cap_add", "security_opt", "binds"} {
		t.Run("unknown-"+key, func(t *testing.T) {
			a := command(t)
			b, _ := json.Marshal(a)
			b = bytes.Replace(b, []byte(`"uid":1000`), []byte(`"`+key+`":false,"uid":1000`), 1)
			if _, e := agentpolicy.Decode(bytes.NewReader(b), agentContext()); e == nil {
				t.Fatal("unknown key accepted")
			}
		})
	}
	for n, b := range map[string][]byte{"duplicate": bytes.Replace(b, []byte(`"generation":1`), []byte(`"generation":1,"generation":2`), 1), "case": bytes.Replace(b, []byte(`"uid":1000`), []byte(`"UID":1000`), 1), "exponent": bytes.Replace(b, []byte(`"generation":1`), []byte(`"generation":1e1`), 1), "trailing": append(append([]byte{}, b...), []byte(`{}`)...)} {
		t.Run(n, func(t *testing.T) {
			if _, e := agentpolicy.Decode(bytes.NewReader(b), agentContext()); e == nil {
				t.Fatal("ambiguous command")
			}
		})
	}
}
func FuzzAgentPolicy(f *testing.F) {
	f.Add([]byte(`{"schema_version":2}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = agentpolicy.Decode(bytes.NewReader(b), agentContext()) })
}

func TestRuntimeInputsRemainOutsideBuild(t *testing.T) {
	p := plan()
	c := ctx()
	c.RuntimeEnvironment = map[string]map[string]string{"web": {"RUNTIME_ONLY": "M08_PRIVATE_VALUE"}}
	c.Secrets = map[string][]contracts.SecretReference{"web": {{ID: id, Version: contracts.Digest(nil), Target: "/run/secrets/token"}}}
	s, e := policy.Finalize(p, c, resolver{})
	if e != nil || s.Services[0].Environment["RUNTIME_ONLY"] != "M08_PRIVATE_VALUE" || len(s.Services[0].Secrets) != 1 {
		t.Fatal("runtime inputs", e)
	}
	b, _ := json.Marshal(p)
	if bytes.Contains(b, []byte("M08_PRIVATE_VALUE")) {
		t.Fatal("build input received runtime data")
	}
	c.RuntimeEnvironment["web"]["APP_MODE"] = "conflict"
	if _, e = policy.Finalize(p, c, resolver{}); e == nil {
		t.Fatal("conflict accepted")
	}
	delete(c.RuntimeEnvironment["web"], "APP_MODE")
	c.Secrets["web"] = append(c.Secrets["web"], c.Secrets["web"][0])
	if _, e = policy.Finalize(p, c, resolver{}); e == nil {
		t.Fatal("duplicate secret target")
	}
	c.Secrets = map[string][]contracts.SecretReference{"absent": {{ID: id, Version: contracts.Digest(nil), Target: "/run/secrets/token"}}}
	if _, e = policy.Finalize(p, c, resolver{}); e == nil {
		t.Fatal("unknown service secrets")
	}
}

type sourcedResolver struct {
	resolver
	source, context, deployment string
}

func (r sourcedResolver) Image(ref string) (policy.Admission, error) {
	a, e := r.resolver.Image(ref)
	a.SourceSHA = r.source
	a.ContextID = r.context
	a.DeploymentID = r.deployment
	return a, e
}
func TestBuiltImageSourceBinding(t *testing.T) {
	p := plan()
	p.Services[0].Image = ""
	p.Services[0].Build = &contracts.LocalBuild{Context: ".", Dockerfile: "Dockerfile", DockerfileDigest: contracts.Digest(nil)}
	c := ctx()
	c.BuiltImages = map[string]string{"web": image}
	r := sourcedResolver{source: c.SHA, context: c.ContextID, deployment: c.DeploymentID}
	if _, e := policy.Finalize(p, c, r); e != nil {
		t.Fatal("bound source", e)
	}
	for _, name := range []string{"source", "context", "deployment"} {
		t.Run(name, func(t *testing.T) {
			bad := r
			switch name {
			case "source":
				bad.source = strings.Repeat("d", 40)
			case "context":
				bad.context = strings.Repeat("d", 64)
			case "deployment":
				bad.deployment = "22222222-2222-4222-8222-222222222222"
			}
			if _, e := policy.Finalize(p, c, bad); e == nil {
				t.Fatal("wrong source identity")
			}
		})
	}
}
