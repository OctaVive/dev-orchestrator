package contracts

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestConfigurationProtocolVersions(t *testing.T) {
	j := buildTestJob()
	j.Version = 2
	j.Clone.Version = 2
	j.PlanHash = Digest([]byte("plan"))
	j.Clone.Configuration = &ConfigurationSettings{Version: 1, Mode: "compose", PolicyHash: Digest([]byte("configuration"))}
	b, _ := json.Marshal(j)
	if _, e := DecodeBuildJob(bytes.NewReader(b), time.Now()); e != nil {
		t.Fatal(e)
	}
	for n, mutate := range map[string]func(*BuildJob){"legacy-clone": func(j *BuildJob) { j.Clone.Version = 1 }, "legacy-build": func(j *BuildJob) { j.Version = 1 }, "missing-plan": func(j *BuildJob) { j.PlanHash = "" }, "mode": func(j *BuildJob) { j.Clone.Configuration.Mode = "shell" }, "policy": func(j *BuildJob) { j.Clone.Configuration.PolicyHash = "stale" }, "expiry": func(j *BuildJob) { j.ExpiresAt = time.Now().Add(-time.Second) }} {
		t.Run(n, func(t *testing.T) {
			c := j
			x := *j.Clone.Configuration
			c.Clone.Configuration = &x
			mutate(&c)
			b, _ := json.Marshal(c)
			if _, e := DecodeBuildJob(bytes.NewReader(b), time.Now()); e == nil {
				t.Fatal("unsafe job")
			}
		})
	}
	for n, b := range map[string][]byte{"nested-unknown": bytes.Replace(b, []byte(`"mode":"compose"`), []byte(`"mode":"compose","ports":[]`), 1), "nested-case": bytes.Replace(b, []byte(`"mode":"compose"`), []byte(`"Mode":"compose"`), 1), "duplicate": bytes.Replace(b, []byte(`"plan_hash":`), []byte(`"plan_hash":"wrong","plan_hash":`), 1), "null": bytes.Replace(b, []byte(`"configuration":{"version":1,"mode":"compose","policy_hash":"`+j.Clone.Configuration.PolicyHash+`"}`), []byte(`"configuration":null`), 1)} {
		t.Run(n, func(t *testing.T) {
			if _, e := DecodeBuildJob(bytes.NewReader(b), time.Now()); e == nil {
				t.Fatal("ambiguous job")
			}
		})
	}
	r := NewCloneResult(j.Clone)
	r.Outcome = "success"
	r.SHA = strings.Repeat("a", 40)
	r.ContextID = strings.Repeat("b", 64)
	r.Entries = 1
	if r.Validate(j.Clone) == nil {
		t.Fatal("success missing plan")
	}
	r.Plan = &ConfigurationPlan{Version: 1, PolicyHash: j.Clone.Configuration.PolicyHash}
	if r.Validate(j.Clone) != nil {
		t.Fatal("plan envelope")
	}
	r.Outcome = "resolved"
	if r.Validate(j.Clone) == nil {
		t.Fatal("plan before success")
	}
}
