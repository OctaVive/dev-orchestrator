// Package policy validates normalized data only. It never parses repositories.
package policy

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"dev-orchestrator/internal/contracts"
)

var ErrDenied = errors.New("configuration_policy_denied")
var ErrAdmission = errors.New("image_admission_required")
var name = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
var imageName = regexp.MustCompile(`^[a-z0-9][a-z0-9.:-]*/[a-z0-9]+([._/-][a-z0-9]+)*@sha256:[a-f0-9]{64}$`)
var target = regexp.MustCompile(`^/data(/[A-Za-z0-9_-]+)*$`)
var healthPath = regexp.MustCompile(`^/[A-Za-z0-9/_-]*$`)

const Profile = "restricted-v1"

// Hash binds the entire immutable grammar/defaults/limits and required control
// set, rather than merely hashing a caller-selected version number.
func Hash() string {
	return contracts.Digest([]byte("configuration-v1;schema-v2;5-services;1-build;offline-run;pinned-images;no-yaml-aliases;readonly-root;drop-all;nnp;private-namespaces;seccomp-mac;no-host-ports;deny-egress;defaults=1000,536870912,128,67108864,67108864,20971520;app=4000,8589934592,512,1342177280,10737418240,104857600;parse=262144,65536,16,10000,5s,128MiB;restart=3;health=30,5,3"))
}
func Defaults() contracts.Resources {
	return contracts.Resources{CPUMillis: 1000, MemoryBytes: 512 << 20, PIDs: 128, TmpBytes: 64 << 20, WritableBytes: 64 << 20, LogBytes: 20 << 20}
}
func validName(s string) bool     { return len(s) <= 63 && name.MatchString(s) }
func ValidImage(s string) bool    { return len(s) <= 512 && imageName.MatchString(s) }
func Text(s string, max int) bool { return len(s) <= max && !strings.ContainsRune(s, 0) }
func argv(v []string) bool {
	if v == nil {
		return true
	}
	if len(v) < 1 || len(v) > 32 {
		return false
	}
	for _, s := range v {
		if !Text(s, 4096) {
			return false
		}
	}
	return v[0] != ""
}
func Environment(v map[string]string) bool {
	if len(v) > 32 {
		return false
	}
	for k, s := range v {
		u := strings.ToUpper(k)
		if !envName.MatchString(k) || !Text(s, 4096) || strings.HasPrefix(u, "ORCH_") || strings.HasPrefix(u, "DOCKER_") || strings.HasPrefix(u, "BUILDKIT_") {
			return false
		}
	}
	return true
}
func resources(r contracts.Resources) bool {
	return r.CPUMillis >= 100 && r.CPUMillis <= 4000 && r.MemoryBytes >= 16<<20 && r.MemoryBytes <= 8<<30 && r.PIDs >= 16 && r.PIDs <= 512 && r.TmpBytes >= 1<<20 && r.TmpBytes <= 256<<20 && r.WritableBytes >= 64<<20 && r.WritableBytes <= 10<<30 && r.LogBytes >= 1<<20 && r.LogBytes <= 20<<20
}
func health(h *contracts.Healthcheck) bool {
	return h == nil || (argv(h.Argv) && len(h.Argv) > 0 && h.IntervalSeconds >= 1 && h.IntervalSeconds <= 300 && h.TimeoutSeconds >= 1 && h.TimeoutSeconds <= 30 && h.TimeoutSeconds <= h.IntervalSeconds && h.Retries >= 1 && h.Retries <= 10)
}
func ports(v []int) bool {
	if len(v) > 16 {
		return false
	}
	seen := map[int]bool{}
	for _, p := range v {
		if p < 1 || p > 65535 || seen[p] {
			return false
		}
		seen[p] = true
	}
	return true
}
func overlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}
func mounts(v []contracts.PlannedMount) bool {
	if len(v) > 8 {
		return false
	}
	for i, m := range v {
		if !validName(m.Name) || len(m.Target) > 128 || !target.MatchString(m.Target) {
			return false
		}
		for _, n := range v[:i] {
			if m.Name == n.Name || overlap(m.Target, n.Target) {
				return false
			}
		}
	}
	return true
}
func ValidatePlan(p contracts.ConfigurationPlan) error {
	b, e := json.Marshal(p)
	if e != nil || len(b) > contracts.MaxPlanBytes || p.Version != 1 || p.PolicyHash != Hash() || !contracts.ValidDigest(p.ConfigDigest) || len(p.Services) < 1 || len(p.Services) > 5 {
		return ErrDenied
	}
	names := map[string]bool{}
	builds := 0
	tot := contracts.Resources{}
	for _, s := range p.Services {
		if !validName(s.Name) || names[s.Name] || !argv(s.Command) || !argv(s.Entrypoint) || !Environment(s.Environment) || !ports(s.Expose) || !mounts(s.Mounts) || !resources(s.Resources) || !health(s.Health) || s.RestartAttempts < 0 || s.RestartAttempts > 3 {
			return ErrDenied
		}
		names[s.Name] = true
		if s.Build != nil {
			builds++
			if s.Image != "" || !contracts.ClonePath(s.Build.Context, true) || !contracts.ClonePath(s.Build.Dockerfile, false) || !contracts.ValidDigest(s.Build.DockerfileDigest) {
				return ErrDenied
			}
		} else if !ValidImage(s.Image) {
			return ErrDenied
		}
		tot.CPUMillis += s.Resources.CPUMillis
		tot.MemoryBytes += s.Resources.MemoryBytes
		tot.PIDs += s.Resources.PIDs
		tot.TmpBytes += s.Resources.TmpBytes
		tot.WritableBytes += s.Resources.WritableBytes
		tot.LogBytes += s.Resources.LogBytes
	}
	if builds > 1 || tot.CPUMillis > 4000 || tot.MemoryBytes > 8<<30 || tot.PIDs > 512 || tot.TmpBytes > 1280<<20 || tot.WritableBytes > 10<<30 || tot.LogBytes > 100<<20 {
		return ErrDenied
	}
	edges := map[string][]string{}
	for _, s := range p.Services {
		seen := map[string]bool{}
		if len(s.DependsOn) > 4 {
			return ErrDenied
		}
		for _, n := range s.DependsOn {
			if n == s.Name || !names[n] || seen[n] {
				return ErrDenied
			}
			seen[n] = true
		}
		edges[s.Name] = s.DependsOn
	}
	state := map[string]int{}
	var visit func(string) bool
	visit = func(n string) bool {
		if state[n] == 1 {
			return false
		}
		if state[n] == 2 {
			return true
		}
		state[n] = 1
		for _, d := range edges[n] {
			if !visit(d) {
				return false
			}
		}
		state[n] = 2
		return true
	}
	for n := range names {
		if !visit(n) {
			return ErrDenied
		}
	}
	return nil
}
func CanonicalPlan(p contracts.ConfigurationPlan) (contracts.ConfigurationPlan, error) {
	if ValidatePlan(p) != nil {
		return p, ErrDenied
	}
	b, _ := json.Marshal(p)
	var c contracts.ConfigurationPlan
	_ = json.Unmarshal(b, &c)
	sort.Slice(c.Services, func(i, j int) bool { return c.Services[i].Name < c.Services[j].Name })
	for i := range c.Services {
		s := &c.Services[i]
		sort.Strings(s.DependsOn)
		sort.Ints(s.Expose)
		sort.Slice(s.Mounts, func(i, j int) bool { return s.Mounts[i].Target < s.Mounts[j].Target })
	}
	return c, nil
}
func PlanHash(p contracts.ConfigurationPlan) string {
	c, e := CanonicalPlan(p)
	if e != nil {
		return ""
	}
	return contracts.ConfigurationDigest(c)
}

// Admission and ownership are supplied by trusted local adapters, never guests.
// Metadata must come from isolated verification of the exact admitted digest.
type Admission struct {
	SourceSHA, ContextID, DeploymentID    string
	ID, Image, PolicyHash, Platform, User string
	Volumes                               []string
	Command, Entrypoint                   []string
	Environment                           map[string]string
	Expose                                []int
}
type Resolver interface {
	Image(image string) (Admission, error)
	Volume(app, name string) (string, error)
	Secret(app, id, version string) error
}
type Context struct {
	RuntimeEnvironment                  map[string]map[string]string
	AppID, DeploymentID, SHA, ContextID string
	BuiltImages                         map[string]string
	Ingress                             contracts.Ingress
	Secrets                             map[string][]contracts.SecretReference
}

func User(s string) (int, int, error) {
	parts := strings.Split(s, ":")
	if len(parts) > 2 {
		return 0, 0, ErrDenied
	}
	parse := func(s string) int {
		if s == "" || strings.Trim(s, "0123456789") != "" {
			return 0
		}
		n := 0
		for _, c := range s {
			n = n*10 + int(c-'0')
			if n > 65535 {
				return 0
			}
		}
		return n
	}
	u := parse(parts[0])
	g := u
	if len(parts) == 2 {
		g = parse(parts[1])
	}
	if u == 0 || g == 0 {
		return 0, 0, ErrDenied
	}
	return u, g, nil
}
func Finalize(p contracts.ConfigurationPlan, c Context, r Resolver) (contracts.RuntimeSpecV2, error) {
	p, e := CanonicalPlan(p)
	if e != nil || r == nil {
		return contracts.RuntimeSpecV2{}, ErrDenied
	}
	names := map[string]bool{}
	for _, s := range p.Services {
		names[s.Name] = true
	}
	for n := range c.Secrets {
		if !names[n] {
			return contracts.RuntimeSpecV2{}, ErrDenied
		}
	}
	for n := range c.RuntimeEnvironment {
		if !names[n] {
			return contracts.RuntimeSpecV2{}, ErrDenied
		}
	}
	out := contracts.RuntimeSpecV2{Version: 2, Profile: Profile, PolicyHash: Hash(), AppID: c.AppID, DeploymentID: c.DeploymentID, SHA: c.SHA, ContextID: c.ContextID, PlanHash: PlanHash(p), Ingress: c.Ingress}
	for _, s := range p.Services {
		image := s.Image
		if s.Build != nil {
			image = c.BuiltImages[s.Name]
		}
		a, e := r.Image(image)
		if e != nil || !ValidImage(image) || a.Image != image || a.PolicyHash != Hash() || (a.ID == "" || len(a.ID) > 128) || a.Platform != "linux/amd64" {
			return contracts.RuntimeSpecV2{}, ErrAdmission
		}
		if s.Build != nil && (a.SourceSHA != c.SHA || a.ContextID != c.ContextID || a.DeploymentID != c.DeploymentID) {
			return contracts.RuntimeSpecV2{}, ErrAdmission
		}
		u, g, e := User(a.User)
		if e != nil || len(a.Volumes) > 0 || !argv(a.Command) || !argv(a.Entrypoint) || !Environment(a.Environment) || !ports(a.Expose) {
			return contracts.RuntimeSpecV2{}, ErrDenied
		}
		v := contracts.RuntimeServiceV2{Name: s.Name, Image: image, AdmissionID: a.ID, UID: u, GID: g, Command: a.Command, Entrypoint: a.Entrypoint, Environment: map[string]string{}, Expose: s.Expose, DependsOn: s.DependsOn, Resources: s.Resources, RestartAttempts: s.RestartAttempts, Health: s.Health, Secrets: c.Secrets[s.Name]}
		if s.Command != nil {
			v.Command = s.Command
		}
		if s.Entrypoint != nil {
			v.Entrypoint = s.Entrypoint
		}
		for k, x := range a.Environment {
			v.Environment[k] = x
		}
		for k, x := range s.Environment {
			v.Environment[k] = x
		}
		for k, x := range c.RuntimeEnvironment[s.Name] {
			if old, ok := s.Environment[k]; ok && old != x {
				return contracts.RuntimeSpecV2{}, ErrDenied
			}
			v.Environment[k] = x
		}
		for _, m := range s.Mounts {
			id, e := r.Volume(c.AppID, m.Name)
			if e != nil || !contracts.ValidJobID(id) {
				return contracts.RuntimeSpecV2{}, ErrDenied
			}
			v.Volumes = append(v.Volumes, contracts.Mount{VolumeID: id, Target: m.Target, ReadOnly: m.ReadOnly})
		}
		out.Services = append(out.Services, v)
	}
	if e = ValidateRuntime(out, r); e != nil {
		return contracts.RuntimeSpecV2{}, e
	}
	return out, nil
}
func ValidateRuntime(s contracts.RuntimeSpecV2, r Resolver) error {
	b, e := json.Marshal(s)
	if e != nil || len(b) > contracts.MaxPlanBytes || s.Version != 2 || s.Profile != Profile || s.PolicyHash != Hash() || !contracts.ValidJobID(s.AppID) || !contracts.ValidJobID(s.DeploymentID) || !contracts.ValidSHA1(s.SHA) || !contracts.ValidDigest("sha256:"+s.ContextID) || !contracts.ValidDigest(s.PlanHash) || r == nil || !healthPath.MatchString(s.Ingress.HealthPath) || len(s.Ingress.HealthPath) > 256 || s.Ingress.Port < 1 || s.Ingress.Port > 65535 {
		return ErrDenied
	}
	p := contracts.ConfigurationPlan{Version: 1, PolicyHash: Hash(), ConfigDigest: s.PlanHash}
	found := false
	for _, v := range s.Services {
		a, e := r.Image(v.Image)
		u, g, ue := User(a.User)
		if e != nil || ue != nil || a.Image != v.Image || a.PolicyHash != Hash() || a.ID != v.AdmissionID || len(v.AdmissionID) == 0 || len(v.AdmissionID) > 128 || a.Platform != "linux/amd64" || len(a.Volumes) > 0 || u != v.UID || g != v.GID {
			return ErrDenied
		}
		ps := contracts.PlannedService{Name: v.Name, Image: v.Image, Command: v.Command, Entrypoint: v.Entrypoint, Environment: v.Environment, Expose: v.Expose, DependsOn: v.DependsOn, Resources: v.Resources, RestartAttempts: v.RestartAttempts, Health: v.Health}
		for _, m := range v.Volumes {
			id, e := r.Volume(s.AppID, m.VolumeID)
			if e != nil || id != m.VolumeID || !contracts.ValidJobID(id) {
				return ErrDenied
			}
			ps.Mounts = append(ps.Mounts, contracts.PlannedMount{Name: "v" + strings.ReplaceAll(id, "-", ""), Target: m.Target, ReadOnly: m.ReadOnly})
		}
		if len(v.Secrets) > 8 {
			return ErrDenied
		}
		seen := map[string]bool{}
		for _, x := range v.Secrets {
			if !contracts.ValidJobID(x.ID) || !contracts.ValidDigest(x.Version) || !regexp.MustCompile(`^/run/secrets/[a-z][a-z0-9_-]{0,62}$`).MatchString(x.Target) || seen[x.Target] || r.Secret(s.AppID, x.ID, x.Version) != nil {
				return ErrDenied
			}
			seen[x.Target] = true
		}
		if v.Name == s.Ingress.Service {
			for _, port := range v.Expose {
				if port == s.Ingress.Port {
					found = true
				}
			}
		}
		p.Services = append(p.Services, ps)
	}
	if !found || ValidatePlan(p) != nil {
		return ErrDenied
	}
	return nil
}
func SpecHash(s contracts.RuntimeSpecV2) string {
	b, _ := json.Marshal(s)
	var c contracts.RuntimeSpecV2
	_ = json.Unmarshal(b, &c)
	sort.Slice(c.Services, func(i, j int) bool { return c.Services[i].Name < c.Services[j].Name })
	for i := range c.Services {
		v := &c.Services[i]
		sort.Strings(v.DependsOn)
		sort.Ints(v.Expose)
		sort.Slice(v.Volumes, func(i, j int) bool { return v.Volumes[i].Target < v.Volumes[j].Target })
		sort.Slice(v.Secrets, func(i, j int) bool { return v.Secrets[i].Target < v.Secrets[j].Target })
	}
	return contracts.ConfigurationDigest(c)
}

// ValidHealthURL intentionally permits only a relative path, never a URL.
func ValidHealthURL(s string) bool {
	u, e := url.Parse(s)
	return e == nil && u.Host == "" && u.Scheme == "" && healthPath.MatchString(s)
}

func ValidName(s string) bool { return validName(s) }
