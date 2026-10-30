//go:build linux

package cloner

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dev-orchestrator/internal/contracts"
)

func TestRefResolutionRejectsAmbiguityAndMovementInputs(t *testing.T) {
	sha := strings.Repeat("a", 40)
	line := sha + "\trefs/heads/main\n"
	if got, e := resolveBranch([]byte(line), "main", 1); e != nil || got != sha {
		t.Fatal(got, e)
	}
	for _, data := range []string{line + line, line + strings.Repeat("b", 40) + "\trefs/heads/other\n", strings.Repeat("a", 64) + "\trefs/heads/main\n", sha + "\trefs/tags/main\n", sha + "\trefs/heads/--evil\n", "garbage", sha + "\trefs/heads/other\n"} {
		if _, e := resolveBranch([]byte(data), "main", 1); e == nil {
			t.Fatal("unsafe advertisement accepted")
		}
	}
}
func TestObjectAndTreeBudgets(t *testing.T) {
	l := contracts.DefaultCloneLimits()
	sha := strings.Repeat("a", 40)
	if validateObjects([]byte(sha+" blob 12\n"), l) != nil {
		t.Fatal("normal object")
	}
	l.ObjectBytes = 11
	if !errors.Is(validateObjects([]byte(sha+" blob 12\n"), l), errLimit) {
		t.Fatal("object size")
	}
	for _, line := range []string{sha + " blob -1\n", sha + " tag 1\n", sha + " blob 99999999999999999999999\n"} {
		if validateObjects([]byte(line), l) == nil {
			t.Fatal("bad object")
		}
	}
	l = contracts.DefaultCloneLimits()
	record := func(mode, kind, name string) string { return mode + " " + kind + " " + sha + "\t" + name + "\x00" }
	if _, e := parseTree([]byte(record("100755", "blob", "run.sh")), l); e != nil {
		t.Fatal(e)
	}
	for _, tree := range []string{record("160000", "commit", "sub"), record("100644", "blob", ".gitmodules"), record("100644", "blob", ".gitattributes"), record("100644", "blob", "../escape"), record("100644", "blob", ".GIT/config"), record("100644", "blob", "file") + record("100644", "blob", "FILE"), record("100644", "blob", "x/y"), record("100644", "blob", "x") + record("100644", "blob", "x/y"), record("100644", "blob", "bad\xff"), record("100644", "blob", "git~1")} {
		if _, e := parseTree([]byte(tree), l); e == nil {
			t.Fatalf("unsafe tree accepted %q", tree)
		}
	}
	l.Entries = 1
	if _, e := parseTree([]byte(record("100644", "blob", "a")+record("100644", "blob", "b")), l); !errors.Is(e, errLimit) {
		t.Fatal("entry quota")
	}
}
func TestSymlinkGraph(t *testing.T) {
	entries := map[string]treeEntry{"dir": {kind: "tree"}, "dir/file": {kind: "blob"}, "a": {mode: "120000", kind: "blob"}, "b": {mode: "120000", kind: "blob"}}
	if target, e := resolveLink("a", entries, map[string]string{"a": "dir/file"}); e != nil || target != "dir/file" {
		t.Fatal(target, e)
	}
	for _, links := range []map[string]string{{"a": "/etc/passwd"}, {"a": "../escape"}, {"a": "b", "b": "a"}, {"a": "missing"}, {"a": "dir/file/extra"}} {
		if _, e := resolveLink("a", entries, links); e == nil {
			t.Fatal("unsafe symlink")
		}
	}
	dirs := map[string]treeEntry{"a": {kind: "tree"}, "b": {kind: "tree"}, "a/to-b": {kind: "blob", mode: "120000"}, "b/to-a": {kind: "blob", mode: "120000"}}
	if validateLinkGraph(dirs, map[string]string{"a/to-b": "../b"}) != nil {
		t.Fatal("safe directory link rejected")
	}
	if validateLinkGraph(dirs, map[string]string{"a/to-b": "../b", "b/to-a": "../a"}) == nil {
		t.Fatal("directory link cycle accepted")
	}
}
func TestOutputCapCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := boundedBuffer{limit: 4, cancel: cancel}
	if _, e := io.Copy(&b, io.LimitReader(strings.NewReader("12345"), 5)); e == nil || ctx.Err() == nil || b.Len() != 0 {
		t.Fatal("unbounded output")
	}
}
func TestRunnerRefusesHost(t *testing.T) {
	if r := Run(context.Background(), contracts.CloneJob{}, nil); r.Outcome != "denied" {
		t.Fatal("host execution")
	}
}

func TestExportCancellationBeforeBlob(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := runner{ctx: ctx, cancel: cancel, dir: t.TempDir()}
	dest := filepath.Join(t.TempDir(), "context")
	j := contracts.CloneJob{ConfigPath: "Dockerfile", BuildContext: ".", Policy: contracts.ClonePolicy{Limits: contracts.DefaultCloneLimits()}}
	// CommandContext observes cancellation before Start, so no Git process or
	// untrusted object parser executes on this host. Export must publish no file.
	_, _, e := r.export([]treeEntry{{mode: "100644", kind: "blob", oid: strings.Repeat("a", 40), name: "Dockerfile"}}, j, dest)
	if e == nil {
		t.Fatal("cancelled export succeeded")
	}
	files, e := os.ReadDir(dest)
	if e != nil || len(files) != 0 {
		t.Fatal("cancelled export wrote content", files, e)
	}
}
func FuzzTree(f *testing.F) {
	f.Add([]byte("100644 blob " + strings.Repeat("a", 40) + "\tDockerfile\x00"))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = parseTree(b, contracts.DefaultCloneLimits()) })
}
