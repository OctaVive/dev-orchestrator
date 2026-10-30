package runtimeagent

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"dev-orchestrator/api"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestExecutionSchemaAndSigningGolden(t *testing.T) {
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	base := "https://contracts.dev-orchestrator.invalid/v1/"
	for _, name := range []string{"common.schema.json", "agent-v2.schema.json", "runtime-v3.schema.json"} {
		b, e := api.Schemas.ReadFile(name)
		if e != nil {
			t.Fatal(e)
		}
		doc, e := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if e != nil {
			t.Fatal(e)
		}
		if e = compiler.AddResource(base+name, doc); e != nil {
			t.Fatal(e)
		}
	}
	schema, e := compiler.Compile(base + "runtime-v3.schema.json")
	if e != nil {
		t.Fatal(e)
	}
	c := command()
	c.ExpiresAt = "2026-10-30T16:00:00Z"
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	if c.Sign(key) != nil {
		t.Fatal("sign")
	}
	b, _ := json.Marshal(c)
	doc, e := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if e != nil || schema.Validate(doc) != nil {
		t.Fatal("valid command does not match schema", e)
	}
	// Freeze signing bytes separately from a signature verification round trip.
	if c.Hash() != "d6c9ba62ac27c6c16199d5b8843e89c24c96030a29978e5f1154e640ecfe5d4c" || c.Signature != "2kLolxv+b2t9Rm+o1NfB63zABrk2+73v5j7PRc5HLMJDwPw9utOi0SsuRcS63VyKRylG42COGpmAWrxA8rjWCw==" {
		t.Fatal("execution signing bytes changed")
	}
	for _, op := range []string{"inspect", "stop", "remove", "logs", "prepare", "probe"} {
		d := c
		d.Operation = op
		if op != "prepare" {
			d.Spec = nil
		}
		if op != "probe" && op != "prepare" {
			d.Target = c.ID
		}
		if op == "logs" {
			d.LogLimit = 10
		}
		d.Sign(key)
		raw, _ := json.Marshal(d)
		doc, e := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if e != nil || schema.Validate(doc) != nil {
			t.Fatal("schema operation", op)
		}
	}
}
