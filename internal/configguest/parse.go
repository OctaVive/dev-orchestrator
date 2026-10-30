// Package configguest parses repository bytes ONLY in disposable guests.
package configguest

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/policy"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
	yaml "go.yaml.in/yaml/v3"
	"golang.org/x/sys/unix"
)

var ErrDenied = policy.ErrDenied
var ErrRead = errors.New("configuration_read_denied")
var ErrDockerfile = errors.New("dockerfile_syntax_denied")

// walk does not resolve aliases. It rejects them and bounds the AST before
// conversion, including duplicate keys and implicit non-string mapping keys.
func walk(n *yaml.Node, depth int, count *int) (any, error) {
	*count++
	if depth > 16 || *count > 10000 || n.Anchor != "" || n.Kind == yaml.AliasNode || n.Style&yaml.TaggedStyle != 0 {
		return nil, ErrDenied
	}
	switch n.Kind {
	case yaml.MappingNode:
		m := map[string]any{}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || k.Value == "<<" || k.Anchor != "" || k.Style&yaml.TaggedStyle != 0 {
				return nil, ErrDenied
			}
			if _, ok := m[k.Value]; ok {
				return nil, ErrDenied
			}
			v, e := walk(n.Content[i+1], depth+1, count)
			if e != nil {
				return nil, e
			}
			m[k.Value] = v
		}
		return m, nil
	case yaml.SequenceNode:
		a := []any{}
		for _, v := range n.Content {
			x, e := walk(v, depth+1, count)
			if e != nil {
				return nil, e
			}
			a = append(a, x)
		}
		return a, nil
	case yaml.ScalarNode:
		if strings.ContainsAny(n.Value, "\x00$") {
			return nil, ErrDenied
		}
		switch n.Tag {
		case "!!str":
			return n.Value, nil
		case "!!bool":
			if n.Value == "true" {
				return true, nil
			}
			if n.Value == "false" {
				return false, nil
			}
		case "!!int":
			if n.Value == "" || strings.Trim(n.Value, "0123456789") != "" || len(n.Value) > 18 {
				return nil, ErrDenied
			}
			v, e := strconv.ParseInt(n.Value, 10, 64)
			if e == nil {
				return v, nil
			}
		}
	}
	return nil, ErrDenied
}

type input struct {
	Services map[string]service           `json:"services"`
	Volumes  map[string]map[string]string `json:"volumes,omitempty"`
}
type build struct {
	Context    string `json:"context"`
	Dockerfile string `json:"dockerfile"`
}
type mount struct {
	Type     string `json:"type"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}
type limits struct {
	CPUs   *string `json:"cpus,omitempty"`
	Memory *string `json:"memory,omitempty"`
	PIDs   *int    `json:"pids,omitempty"`
}
type deploy struct {
	Resources struct {
		Limits limits `json:"limits"`
	} `json:"resources"`
}
type health struct {
	Test     []string `json:"test"`
	Interval string   `json:"interval"`
	Timeout  string   `json:"timeout"`
	Retries  int      `json:"retries"`
}
type service struct {
	Image       string            `json:"image,omitempty"`
	Build       *build            `json:"build,omitempty"`
	Command     []string          `json:"command,omitempty"`
	Entrypoint  []string          `json:"entrypoint,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	Expose      []string          `json:"expose,omitempty"`
	DependsOn   []string          `json:"depends_on,omitempty"`
	Volumes     []mount           `json:"volumes,omitempty"`
	Deploy      *deploy           `json:"deploy,omitempty"`
	Restart     string            `json:"restart,omitempty"`
	Health      *health           `json:"healthcheck,omitempty"`
}

func Compose(data []byte) (contracts.ConfigurationPlan, error) {
	z := contracts.ConfigurationPlan{}
	if len(data) == 0 || len(data) > contracts.MaxConfigurationBytes || !utf8.Valid(data) || bytes.ContainsRune(data, 0) {
		return z, ErrDenied
	}
	d := yaml.NewDecoder(bytes.NewReader(data))
	var doc, extra yaml.Node
	if d.Decode(&doc) != nil || d.Decode(&extra) != io.EOF || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return z, ErrDenied
	}
	count := 0
	value, e := walk(doc.Content[0], 0, &count)
	if e != nil {
		return z, e
	}
	b, e := json.Marshal(value)
	if e != nil {
		return z, ErrDenied
	}
	var in input
	j := json.NewDecoder(bytes.NewReader(b))
	j.DisallowUnknownFields()
	if j.Decode(&in) != nil {
		return z, ErrDenied
	}
	p := contracts.ConfigurationPlan{Version: 1, PolicyHash: policy.Hash(), ConfigDigest: contracts.Digest(data)}
	for n, v := range in.Volumes {
		if !policy.ValidName(n) || len(v) != 0 || len(in.Volumes) > 8 {
			return z, ErrDenied
		}
	}
	for n, s := range in.Services {
		v := contracts.PlannedService{Name: n, Image: s.Image, Command: s.Command, Entrypoint: s.Entrypoint, Environment: s.Environment, DependsOn: s.DependsOn, Resources: policy.Defaults(), RestartAttempts: 0}
		if s.Deploy != nil {
			l := s.Deploy.Resources.Limits
			if l.CPUs != nil {
				x, ok := cpu(*l.CPUs)
				if !ok {
					return z, ErrDenied
				}
				v.Resources.CPUMillis = x
			}
			if l.Memory != nil {
				x, ok := memory(*l.Memory)
				if !ok {
					return z, ErrDenied
				}
				v.Resources.MemoryBytes = x
			}
			if l.PIDs != nil {
				v.Resources.PIDs = *l.PIDs
			}
		}
		switch s.Restart {
		case "", "no":
		case "on-failure:1":
			v.RestartAttempts = 1
		case "on-failure:2":
			v.RestartAttempts = 2
		case "on-failure:3":
			v.RestartAttempts = 3
		default:
			return z, ErrDenied
		}
		if s.Build != nil {
			if !contracts.ClonePath(s.Build.Context, true) || !contracts.ClonePath(s.Build.Dockerfile, false) {
				return z, ErrDenied
			}
			v.Build = &contracts.LocalBuild{Context: s.Build.Context, Dockerfile: s.Build.Dockerfile, DockerfileDigest: contracts.Digest(nil)}
		}
		for _, port := range s.Expose {
			if port == "" || strings.Trim(port, "0123456789") != "" || len(port) > 5 {
				return z, ErrDenied
			}
			x, e := strconv.Atoi(port)
			if e != nil {
				return z, ErrDenied
			}
			v.Expose = append(v.Expose, x)
		}
		for _, m := range s.Volumes {
			if m.Type != "volume" {
				return z, ErrDenied
			}
			if _, ok := in.Volumes[m.Source]; !ok {
				return z, ErrDenied
			}
			v.Mounts = append(v.Mounts, contracts.PlannedMount{Name: m.Source, Target: m.Target, ReadOnly: m.ReadOnly})
		}
		if s.Health != nil {
			h := s.Health
			if len(h.Test) < 2 || h.Test[0] != "CMD" {
				return z, ErrDenied
			}
			interval, ok := seconds(h.Interval)
			timeout, tok := seconds(h.Timeout)
			if !ok || !tok {
				return z, ErrDenied
			}
			v.Health = &contracts.Healthcheck{Argv: h.Test[1:], IntervalSeconds: interval, TimeoutSeconds: timeout, Retries: h.Retries}
		}
		p.Services = append(p.Services, v)
	}
	return policy.CanonicalPlan(p)
}
func Dockerfile(data []byte) error {
	if len(data) == 0 || len(data) > 64<<10 || !utf8.Valid(data) || bytes.ContainsAny(data, "\x00\r`") {
		return ErrDenied
	}
	if _, _, _, ok := parser.DetectSyntax(data); ok {
		return ErrDenied
	}
	for _, key := range []string{"escape", "check"} {
		if _, _, _, ok := parser.ParseDirective(key, data); ok {
			return ErrDenied
		}
	}
	for _, line := range strings.Split(string(data), "\n") {
		v := strings.Map(func(r rune) rune {
			if unicode.IsSpace(r) {
				return -1
			}
			return r
		}, strings.TrimSpace(line))
		if strings.HasPrefix(v, "#") && (strings.Contains(strings.ToLower(v), "syntax=") || strings.Contains(strings.ToLower(v), "escape=") || strings.Contains(strings.ToLower(v), "check=")) {
			return ErrDenied
		}
	}
	ast, e := parser.Parse(bytes.NewReader(data))
	if e != nil || len(ast.AST.Children) == 0 || len(ast.AST.Children) > 1024 {
		return ErrDenied
	}
	stages := map[string]bool{}
	stageCount := 0
	for _, n := range ast.AST.Children {
		args := []string{}
		for a := n.Next; a != nil; a = a.Next {
			args = append(args, a.Value)
		}
		if len(args) == 0 || len(n.Heredocs) > 0 {
			return ErrDenied
		}
		op := strings.ToLower(n.Value)
		switch op {
		case "from":
			if len(n.Flags) > 0 || len(args) != 1 && len(args) != 3 || strings.ContainsAny(args[0], "$\\") {
				return ErrDenied
			}
			base := args[0]
			if base != "scratch" && !stages[strings.ToLower(base)] && !policy.ValidImage(base) {
				return ErrDenied
			}
			if len(args) == 3 {
				a := strings.ToLower(args[2])
				if !strings.EqualFold(args[1], "as") || stages[a] || a == "scratch" || strings.Trim(a, "abcdefghijklmnopqrstuvwxyz0123456789_-") != "" || a == "" {
					return ErrDenied
				}
				stages[a] = true
			}
			stages[strconv.Itoa(stageCount)] = true
			stageCount++
		case "copy":
			if stageCount == 0 || len(args) < 2 {
				return ErrDenied
			}
			for _, f := range n.Flags {
				if !strings.HasPrefix(f, "--from=") || !stages[strings.ToLower(strings.TrimPrefix(f, "--from="))] {
					return ErrDenied
				}
			}
			for _, a := range args[:len(args)-1] {
				if strings.Contains(a, "://") || strings.ContainsRune(a, 0) {
					return ErrDenied
				}
			}
		case "run", "user", "workdir", "env", "expose", "cmd", "entrypoint", "label":
			if stageCount == 0 || len(n.Flags) > 0 {
				return ErrDenied
			}
			if (op == "cmd" || op == "entrypoint") && !n.Attributes["json"] {
				return ErrDenied
			}
		default:
			return ErrDenied
		}
	}
	if stageCount == 0 {
		return ErrDenied
	}
	return nil
}

// Read beneath an os.Root, rejecting symlinks on every component. Before build,
// a fresh normalizer invocation checks the exact selected Dockerfile digest.
func read(root *os.Root, p string, limit int64) ([]byte, error) {
	if !contracts.ClonePath(p, false) {
		return nil, ErrDenied
	}
	parts := strings.Split(p, "/")
	for i := range parts {
		st, e := root.Lstat(strings.Join(parts[:i+1], "/"))
		if e != nil || st.Mode()&os.ModeSymlink != 0 {
			return nil, ErrDenied
		}
	}
	f, e := root.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, ErrDenied
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() {
		return nil, ErrDenied
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, ErrDenied
	}
	return b, nil
}
func Repository(dir, mode, config string) (contracts.ConfigurationPlan, error) {
	root, e := os.OpenRoot(dir)
	if e != nil {
		return contracts.ConfigurationPlan{}, ErrDenied
	}
	defer root.Close()
	limit := int64(contracts.MaxConfigurationBytes)
	if mode == "dockerfile" {
		limit = 64 << 10
	}
	data, e := read(root, config, limit)
	if e != nil {
		return contracts.ConfigurationPlan{}, ErrRead
	}
	var p contracts.ConfigurationPlan
	switch mode {
	case "compose":
		p, e = Compose(data)
		if e != nil {
			return p, e
		}
	case "dockerfile":
		p = contracts.ConfigurationPlan{Version: 1, PolicyHash: policy.Hash(), ConfigDigest: contracts.Digest(data), Services: []contracts.PlannedService{{Name: "web", Build: &contracts.LocalBuild{Context: ".", Dockerfile: config, DockerfileDigest: contracts.Digest(data)}, Resources: policy.Defaults(), Expose: []int{8080}}}}
	default:
		return p, ErrDenied
	}
	for i := range p.Services {
		b := p.Services[i].Build
		if b == nil {
			continue
		}
		if mode == "compose" {
			b.Context = path.Join(path.Dir(config), b.Context)
		}
		data, e := read(root, path.Join(b.Context, b.Dockerfile), 64<<10)
		if e != nil {
			return p, ErrRead
		}
		if Dockerfile(data) != nil {
			return p, ErrDockerfile
		}
		b.DockerfileDigest = contracts.Digest(data)
	}
	sort.Slice(p.Services, func(i, j int) bool { return p.Services[i].Name < p.Services[j].Name })
	return policy.CanonicalPlan(p)
}

func seconds(s string) (int, bool) {
	if !strings.HasSuffix(s, "s") {
		return 0, false
	}
	v := strings.TrimSuffix(s, "s")
	if v == "" || len(v) > 3 || strings.Trim(v, "0123456789") != "" {
		return 0, false
	}
	n, e := strconv.Atoi(v)
	return n, e == nil
}
func cpu(s string) (int, bool) {
	p := strings.Split(s, ".")
	if len(p) > 2 || len(p[0]) != 1 || p[0][0] < '0' || p[0][0] > '4' {
		return 0, false
	}
	n := int(p[0][0]-'0') * 1000
	if len(p) == 2 {
		if len(p[1]) < 1 || len(p[1]) > 3 || strings.Trim(p[1], "0123456789") != "" {
			return 0, false
		}
		x, e := strconv.Atoi(p[1] + strings.Repeat("0", 3-len(p[1])))
		if e != nil {
			return 0, false
		}
		n += x
	}
	return n, n >= 100 && n <= 4000
}
func memory(s string) (int64, bool) {
	if len(s) < 2 || len(s) > 8 {
		return 0, false
	}
	unit := s[len(s)-1]
	v := s[:len(s)-1]
	if strings.Trim(v, "0123456789") != "" {
		return 0, false
	}
	n, e := strconv.ParseInt(v, 10, 64)
	if e != nil || n < 1 || n > 8192 {
		return 0, false
	}
	switch unit {
	case 'm', 'M':
		n *= 1 << 20
	case 'g', 'G':
		n *= 1 << 30
	default:
		return 0, false
	}
	return n, n >= 16<<20 && n <= 8<<30
}
