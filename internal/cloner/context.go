//go:build linux

package cloner

import (
	"bytes"
	"os"
	"path"
	"strings"
	"unicode/utf8"

	"dev-orchestrator/internal/contracts"
)

type treeEntry struct{ mode, kind, oid, name string }

func parseTree(data []byte, l contracts.CloneLimits) ([]treeEntry, error) {
	if len(data) == 0 || data[len(data)-1] != 0 {
		return nil, errDenied
	}
	records := bytes.Split(data[:len(data)-1], []byte{0})
	if len(records) > l.Entries {
		return nil, errLimit
	}
	result := make([]treeEntry, 0, len(records))
	seen := map[string]bool{}
	for _, record := range records {
		left, name, ok := bytes.Cut(record, []byte{'\t'})
		p := strings.Fields(string(left))
		if !ok || len(p) != 3 || !contracts.ValidSHA1(p[2]) || !utf8.Valid(name) || !contracts.ClonePath(string(name), false) {
			return nil, errDenied
		}
		n := string(name)
		key := strings.ToLower(n)
		if seen[key] {
			return nil, errDenied
		}
		seen[key] = true
		if len(n) > l.PathBytes || len(strings.Split(n, "/")) > l.Depth {
			return nil, errLimit
		}
		for _, part := range strings.Split(key, "/") {
			if part == ".gitmodules" || part == ".gitattributes" || part == ".lfsconfig" || part == "git~1" {
				return nil, errDenied
			}
		}
		if !((p[0] == "040000" && p[1] == "tree") || ((p[0] == "100644" || p[0] == "100755" || p[0] == "120000") && p[1] == "blob")) {
			return nil, errDenied
		}
		result = append(result, treeEntry{p[0], p[1], p[2], n})
	}
	// Every ancestor must be an explicit tree; no file may parent another entry.
	byName := map[string]treeEntry{}
	for _, e := range result {
		byName[e.name] = e
	}
	for _, e := range result {
		for parent := path.Dir(e.name); parent != "."; parent = path.Dir(parent) {
			if byName[parent].kind != "tree" {
				return nil, errDenied
			}
		}
	}
	return result, nil
}

func insideContext(name, context string) bool {
	return context == "." || strings.HasPrefix(name, context+"/")
}

func resolveLink(name string, entries map[string]treeEntry, links map[string]string) (string, error) {
	parts := strings.Split(name, "/")
	resolved := []string{}
	steps := 0
	for len(parts) > 0 {
		part := parts[0]
		parts = parts[1:]
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			if len(resolved) == 0 {
				return "", errDenied
			}
			resolved = resolved[:len(resolved)-1]
			continue
		}
		resolved = append(resolved, part)
		key := strings.Join(resolved, "/")
		if target, ok := links[key]; ok {
			steps++
			if steps > 64 || target == "" || strings.HasPrefix(target, "/") || strings.ContainsAny(target, "\\\x00:\r\n") {
				return "", errDenied
			}
			resolved = resolved[:len(resolved)-1]
			parts = append(strings.Split(target, "/"), parts...)
		} else if len(parts) > 0 && entries[key].kind != "tree" {
			return "", errDenied
		}
	}
	key := strings.Join(resolved, "/")
	if _, ok := entries[key]; !ok {
		return "", errDenied
	}
	return key, nil
}

// Directory containment plus directory symlinks must form a DAG. Resolving each
// individual target alone misses cycles such as a/to-b -> ../b, b/to-a -> ../a.
func validateLinkGraph(entries map[string]treeEntry, links map[string]string) error {
	edges := map[string][]string{}
	for name, e := range entries {
		if e.kind == "tree" {
			edges[path.Dir(name)] = append(edges[path.Dir(name)], name)
		}
	}
	for name := range links {
		target, e := resolveLink(name, entries, links)
		if e != nil {
			return e
		}
		if entries[target].kind == "tree" {
			edges[path.Dir(name)] = append(edges[path.Dir(name)], target)
		}
	}
	type frame struct {
		name string
		next int
	}
	state := map[string]byte{}
	for start := range edges {
		if state[start] != 0 {
			continue
		}
		state[start] = 1
		stack := []frame{{name: start}}
		for len(stack) > 0 {
			top := &stack[len(stack)-1]
			children := edges[top.name]
			if top.next == len(children) {
				state[top.name] = 2
				stack = stack[:len(stack)-1]
				continue
			}
			child := children[top.next]
			top.next++
			if state[child] == 1 {
				return errDenied
			}
			if state[child] == 0 {
				state[child] = 1
				stack = append(stack, frame{name: child})
			}
		}
	}
	return nil
}

func (r *runner) export(entries []treeEntry, j contracts.CloneJob, dest string) (int, int64, error) {
	all := map[string]treeEntry{}
	links := map[string]string{}
	for _, e := range entries {
		all[e.name] = e
	}
	if j.BuildContext != "." && all[j.BuildContext].kind != "tree" {
		return 0, 0, errDenied
	}
	config, ok := all[j.ConfigPath]
	if !ok || config.kind != "blob" || config.mode == "120000" || !insideContext(j.ConfigPath, j.BuildContext) {
		return 0, 0, errDenied
	}
	// Load symlink targets first, validate the complete graph before writing.
	for _, e := range entries {
		if e.mode == "120000" {
			b, err := r.git(int64(j.Policy.Limits.PathBytes), "cat-file", "blob", e.oid)
			if err != nil {
				return 0, 0, err
			}
			if !utf8.Valid(b) {
				return 0, 0, errDenied
			}
			links[e.name] = string(b)
		}
	}
	for name := range links {
		target, err := resolveLink(name, all, links)
		if err != nil {
			return 0, 0, err
		}
		if insideContext(name, j.BuildContext) && !insideContext(target, j.BuildContext) {
			return 0, 0, errDenied
		}
	}
	if e := validateLinkGraph(all, links); e != nil {
		return 0, 0, e
	}
	if j.BuildContext != "." {
		// Validate again after rebasing the selected subtree. A link such as
		// ../src/file may resolve inside the repository's src tree, but escapes
		// the exported context and changes meaning once src is its root.
		selected := map[string]treeEntry{}
		selectedLinks := map[string]string{}
		for name, e := range all {
			if insideContext(name, j.BuildContext) {
				selected[strings.TrimPrefix(name, j.BuildContext+"/")] = e
			}
		}
		for name, target := range links {
			if insideContext(name, j.BuildContext) {
				selectedLinks[strings.TrimPrefix(name, j.BuildContext+"/")] = target
			}
		}
		for name := range selectedLinks {
			if _, e := resolveLink(name, selected, selectedLinks); e != nil {
				return 0, 0, e
			}
		}
	}
	if os.Mkdir(dest, 0700) != nil {
		return 0, 0, errDenied
	}
	root, err := os.OpenRoot(dest)
	if err != nil {
		return 0, 0, errDenied
	}
	defer root.Close()
	count := 0
	var size int64
	for _, e := range entries {
		if e.kind == "tree" || !insideContext(e.name, j.BuildContext) {
			continue
		}
		name := e.name
		if j.BuildContext != "." {
			name = strings.TrimPrefix(name, j.BuildContext+"/")
		}
		if err = root.MkdirAll(path.Dir(name), 0700); err != nil {
			return 0, 0, errDenied
		}
		if e.mode == "120000" {
			continue
		}
		blob, err := r.git(j.Policy.Limits.ObjectBytes, "cat-file", "blob", e.oid)
		if err != nil {
			return 0, 0, err
		}
		if bytes.HasPrefix(blob, []byte("version https://git-lfs.github.com/spec/v1")) {
			return 0, 0, errDenied
		}
		if int64(len(blob)) > j.Policy.Limits.ContextBytes-size {
			return 0, 0, errLimit
		}
		size += int64(len(blob))
		count++
		mode := os.FileMode(0600)
		if e.mode == "100755" {
			mode = 0700
		}
		f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return 0, 0, errDenied
		}
		_, err = f.Write(blob)
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			return 0, 0, errDenied
		}
	}
	for _, e := range entries {
		if e.mode == "120000" && insideContext(e.name, j.BuildContext) {
			name := e.name
			if j.BuildContext != "." {
				name = strings.TrimPrefix(name, j.BuildContext+"/")
			}
			if int64(len(links[e.name])) > j.Policy.Limits.ContextBytes-size {
				return 0, 0, errLimit
			}
			if root.Symlink(links[e.name], name) != nil {
				return 0, 0, errDenied
			}
			size += int64(len(links[e.name]))
			count++
		}
	}
	if normalizeContextModes(root, entries, j.BuildContext) != nil {
		return 0, 0, errDenied
	}
	return count, size, nil
}

// Keep the context root private, while preserving Git's canonical content modes
// for Docker COPY. Private staging modes (0600/0700) must not become image modes:
// those make root-owned copied executables inaccessible to a nonroot workload.
func normalizeContextModes(root *os.Root, entries []treeEntry, context string) error {
	for _, entry := range entries {
		if !insideContext(entry.name, context) {
			continue
		}
		name := entry.name
		if context != "." {
			name = strings.TrimPrefix(name, context+"/")
		}
		var mode os.FileMode
		switch entry.mode {
		case "040000", "100755":
			mode = 0755
		case "100644":
			mode = 0644
		case "120000":
			continue
		default:
			return errDenied
		}
		if root.Chmod(name, mode) != nil {
			return errDenied
		}
	}
	return nil
}
