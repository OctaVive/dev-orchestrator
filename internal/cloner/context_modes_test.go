//go:build linux

package cloner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateContextPreservesGitContentModes(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bin/run", "readme"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("known fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	entries := []treeEntry{{mode: "040000", kind: "tree", name: "bin"}, {mode: "100755", kind: "blob", name: "bin/run"}, {mode: "100644", kind: "blob", name: "readme"}}
	if err = normalizeContextModes(root, entries, "."); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]os.FileMode{".": 0700, "bin": 0755, "bin/run": 0755, "readme": 0644} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil || st.Mode().Perm() != want {
			t.Fatalf("%s mode: %v %v", name, st, err)
		}
	}
	if err = normalizeContextModes(root, []treeEntry{{mode: "100777", name: "readme"}}, "."); err == nil {
		t.Fatal("non-Git permission mode admitted")
	}
	if err = normalizeContextModes(root, []treeEntry{{mode: "100755", name: "../foreign"}}, "."); err == nil {
		t.Fatal("context boundary escaped")
	}
}
