package contracts

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"
	"unicode"

	"dev-orchestrator/api"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const schemaBase = "https://contracts.dev-orchestrator.invalid/v1/"

// Validator uses trusted embedded schemas, never request-supplied schemas.
// Construct once at startup and share for read-only validation.
type Validator struct {
	deployment *jsonschema.Schema
	agent      *jsonschema.Schema
	agentV2    *jsonschema.Schema
	login      *jsonschema.Schema
	buildLease *jsonschema.Schema
}

func NewValidator() (*Validator, error) {
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	for _, name := range []string{"common.schema.json", "deployment.schema.json", "agent.schema.json", "agent-v2.schema.json", "login.schema.json", "build-lease.schema.json"} {
		b, err := api.Schemas.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("load embedded schema %s: %w", name, err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			return nil, fmt.Errorf("parse embedded schema %s: %w", name, err)
		}
		if err := c.AddResource(schemaBase+name, doc); err != nil {
			return nil, fmt.Errorf("register embedded schema %s: %w", name, err)
		}
	}
	deployment, err := c.Compile(schemaBase + "deployment.schema.json")
	if err != nil {
		return nil, fmt.Errorf("compile deployment schema: %w", err)
	}
	agent, err := c.Compile(schemaBase + "agent.schema.json")
	if err != nil {
		return nil, fmt.Errorf("compile agent schema: %w", err)
	}
	login, err := c.Compile(schemaBase + "login.schema.json")
	if err != nil {
		return nil, fmt.Errorf("compile login schema: %w", err)
	}
	buildLease, err := c.Compile(schemaBase + "build-lease.schema.json")
	if err != nil {
		return nil, fmt.Errorf("compile build lease schema: %w", err)
	}
	agentV2, err := c.Compile(schemaBase + "agent-v2.schema.json")
	if err != nil {
		return nil, err
	}
	return &Validator{deployment: deployment, agent: agent, agentV2: agentV2, login: login, buildLease: buildLease}, nil
}

const MaxCredentialsBytes = 8 << 10

// Credentials is an input-only DTO. Never log it or reuse it as a response.
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (v *Validator) DecodeCredentials(r io.Reader) (Credentials, error) {
	b, err := readObject(r, MaxCredentialsBytes)
	if err != nil {
		return Credentials{}, err
	}
	if err := validateSchema(v.login, b); err != nil {
		return Credentials{}, err
	}
	return decodeTyped[Credentials](b)
}

func validateSchema(s *jsonschema.Schema, b []byte) error {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		return ErrMalformedJSON
	}
	if err := s.Validate(doc); err != nil {
		// Schema errors can contain environment values; never propagate them.
		return ErrSchema
	}
	return nil
}

func (v *Validator) DecodeDeployment(r io.Reader) (DeploymentRequest, error) {
	var zero DeploymentRequest
	b, err := readObject(r, MaxDeploymentBytes)
	if err != nil {
		return zero, err
	}
	if err := validateSchema(v.deployment, b); err != nil {
		return zero, err
	}
	request, err := decodeTyped[DeploymentRequest](b)
	if err != nil {
		return zero, err
	}
	if !ValidCloneInput(request.RepositoryURL, request.Branch, request.ConfigPath, request.BuildContext) ||
		!validMounts(request.Volumes) || !validEnvironment(request.Environment) {
		return zero, ErrInvalidRequest
	}
	return request, nil
}

// CommandContext must come from authenticated worker identity and durable agent
// per-app state. Comparing LastGeneration is only a preliminary check: signature
// verification and an atomic replay ledger are mandatory before execution.
type CommandContext struct {
	WorkerID       string
	LastGeneration int64
	Now            time.Time
}

// DecodeAgentCommand validates shape and context only; it DOES NOT verify the
// signature, approval, registry ownership, volume ownership or engine policy.
func (v *Validator) DecodeAgentCommand(r io.Reader, ctx CommandContext) (AgentCommand, error) {
	var zero AgentCommand
	b, err := readObject(r, MaxCommandBytes)
	if err != nil {
		return zero, err
	}
	if err := validateSchema(v.agent, b); err != nil {
		return zero, err
	}
	command, err := decodeTyped[AgentCommand](b)
	if err != nil {
		return zero, err
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(command.Signature)
	if err != nil || len(sig) != 64 {
		return zero, ErrSchema
	}
	if ctx.WorkerID == "" || ctx.Now.IsZero() || ctx.LastGeneration < 0 ||
		command.WorkerID != ctx.WorkerID || command.Generation <= ctx.LastGeneration ||
		!command.ExpiresAt.After(ctx.Now) || command.ExpiresAt.After(ctx.Now.Add(5*time.Minute)) {
		return zero, ErrCommandContext
	}
	names := make(map[string]bool)
	for _, service := range command.Spec.Services {
		if names[service.Name] || !validMounts(service.Volumes) || !validEnvironment(service.Environment) {
			return zero, ErrSchema
		}
		names[service.Name] = true
	}
	if !names[command.Spec.Ingress.Service] {
		return zero, ErrSchema
	}
	return command, nil
}

// This is lexical validation only. Approved-origin selection, DNS/IP validation,
// redirect rules and externally enforced egress are NOT implemented here.
func validRepositoryURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Port() != "" && u.Port() != "443" {
		return false
	}
	host := u.Hostname()
	if !validPublicHostnameShape(host) || net.ParseIP(host) != nil || u.Path == "" || u.Path == "/" ||
		strings.ContainsAny(raw, "\\%") || strings.ContainsAny(u.Path, " \t\r\n") {
		return false
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func validPublicHostnameShape(host string) bool {
	if len(host) > 253 || !strings.Contains(host, ".") || host != strings.ToLower(host) {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	for _, suffix := range []string{".localhost", ".local", ".internal", ".invalid", ".test"} {
		if strings.HasSuffix(host, suffix) {
			return false
		}
	}
	return true
}

func validBranch(branch string) bool {
	if branch == "" || branch == "@" || strings.HasPrefix(branch, "-") || strings.HasPrefix(branch, "refs/") ||
		strings.HasSuffix(branch, ".") || strings.Contains(branch, "..") || strings.Contains(branch, "@{") ||
		strings.ContainsAny(branch, " ~^:?*[\\") {
		return false
	}
	for _, c := range branch {
		if unicode.IsControl(c) || unicode.IsSpace(c) {
			return false
		}
	}
	for _, part := range strings.Split(branch, "/") {
		if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	return true
}

func validEnvironment(env map[string]string) bool {
	for k := range env {
		upper := strings.ToUpper(k)
		for _, prefix := range []string{"ORCH_", "DOCKER_", "BUILDKIT_"} {
			if strings.HasPrefix(upper, prefix) {
				return false
			}
		}
	}
	return true
}

func validMounts(mounts []Mount) bool {
	for i, mount := range mounts {
		for _, other := range mounts[:i] {
			if mount.VolumeID == other.VolumeID || mount.Target == other.Target ||
				strings.HasPrefix(mount.Target, other.Target+"/") || strings.HasPrefix(other.Target, mount.Target+"/") {
				return false
			}
		}
	}
	return true
}

// DecodeAgentCommandV2Shape is structural only; agentpolicy performs semantic
// checks and M09 must add signature/replay/authorization before any operation.
func (v *Validator) DecodeAgentCommandV2Shape(r io.Reader) (AgentCommandV2, error) {
	var z AgentCommandV2
	b, e := readObject(r, MaxPlanBytes)
	if e != nil {
		return z, e
	}
	if e = validateSchema(v.agentV2, b); e != nil {
		return z, e
	}
	return DecodeConfiguration[AgentCommandV2](bytes.NewReader(b))
}
