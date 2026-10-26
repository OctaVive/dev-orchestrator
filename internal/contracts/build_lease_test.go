package contracts

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestBuildLeaseStrictContractAndDeadline(t *testing.T) {
	v := validator(t)
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	base := fixture(t, "build-lease")
	r, err := v.DecodeBuildLease(bytes.NewReader(base), now)
	if err != nil || r.ProfileID != "build-small-v1" || r.ExpiresAt.Location() != time.UTC {
		t.Fatal("valid lease rejected", err)
	}
	for _, edit := range []func(map[string]any){
		func(d map[string]any) { d["schema_version"] = 2 },
		func(d map[string]any) { delete(d, "command_id") },
		func(d map[string]any) { d["job_id"] = "--shell" },
		func(d map[string]any) { d["template_id"] = "../../host" },
		func(d map[string]any) { d["profile_id"] = "privileged" },
		func(d map[string]any) { d["nonce"] = "reused-short-nonce" },
		func(d map[string]any) { d["expires_at"] = "2030-01-01T00:00:00Z" },
		func(d map[string]any) { d["expires_at"] = "2030-01-01T00:30:01Z" },
		func(d map[string]any) { d["expires_at"] = "never" },
		func(d map[string]any) { d["host_path"] = "/etc" },
		func(d map[string]any) { d["xml"] = "<domain/>" },
		func(d map[string]any) { d["controller_id"] = "from-browser" },
		func(d map[string]any) { d["network"] = "management" },
		func(d map[string]any) { d["vcpus"] = 999 },
		func(d map[string]any) { d["Job_ID"] = d["job_id"] },
	} {
		if _, err := v.DecodeBuildLease(bytes.NewReader(mutate(t, base, edit)), now); err == nil {
			t.Fatal("unsafe lease accepted")
		}
	}
	if _, err := v.DecodeBuildLease(bytes.NewReader(base), time.Time{}); !errors.Is(err, ErrCommandContext) {
		t.Fatal("missing trusted clock accepted")
	}
	if _, err := v.DecodeBuildLease(strings.NewReader(strings.Repeat(" ", MaxBuildLeaseBytes+1)), now); !errors.Is(err, ErrTooLarge) {
		t.Fatal("oversized lease accepted")
	}
}

func TestReleaseAcceptsOnlyEmptyObject(t *testing.T) {
	if err := DecodeEmptyObject(strings.NewReader(" {} \n")); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`null`, `[]`, `{} {}`, `{"path":"/"}`, `{"x":1,"x":2}`, strings.Repeat(" ", 1025)} {
		if err := DecodeEmptyObject(strings.NewReader(body)); err == nil {
			t.Fatal("release body accepted", body)
		}
	}
}

func FuzzBuildLeaseDecode(f *testing.F) {
	v, err := NewValidator()
	if err != nil {
		f.Fatal(err)
	}
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	f.Add([]byte(`{"schema_version":1}`))
	f.Add([]byte(`{"job_id":"one","job_id":"two"}`))
	seed, err := os.ReadFile("../../tests/fixtures/contracts/build-lease.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = v.DecodeBuildLease(bytes.NewReader(b), now) })
}
