//go:build linux

// ingest-runner has two fixed phases, supervised by trusted guest init. The
// validator and scanner use different UIDs; management never supplies paths.
package main

import (
	"bytes"
	"context"
	"dev-orchestrator/internal/contracts"
	"dev-orchestrator/internal/ingest"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	phase := flag.String("phase", "", "validate or scan")
	flag.Parse()
	if *phase != "validate" && *phase != "scan" && *phase != "deny" {
		os.Exit(19)
	}
	marker, e := os.Lstat("/run/orchestrator-ingest-worker")
	if e != nil || !marker.IsDir() || marker.Mode()&0022 != 0 || marker.Sys().(*syscall.Stat_t).Uid != 0 || (*phase == "validate" && os.Geteuid() != 1000) || ((*phase == "scan" || *phase == "deny") && os.Geteuid() != 1001) {
		os.Exit(20)
	}
	input, e := os.Open("/dev/vdb")
	if e != nil {
		os.Exit(21)
	}
	defer input.Close()
	j, e := contracts.ReadBuildInput(input, time.Now())
	if e != nil {
		os.Exit(22)
	}
	result := contracts.ArtifactResult{Version: 1, JobID: j.Clone.JobID, DeploymentID: j.Clone.DeploymentID, Attempt: j.Clone.Attempt, Generation: j.Clone.Generation, PolicyHash: j.PolicyHash, Outcome: "denied"}
	if *phase == "validate" {
		artifact, e := os.Open("/dev/vdc")
		if e != nil {
			os.Exit(24)
		}
		defer artifact.Close()
		v, e := ingest.Validate(artifact, "/work", j.Policy.Limits)
		if e == nil {
			b, e := json.Marshal(v)
			if e == nil && len(b) <= 4096 && os.WriteFile("/work/verified.json", b, 0600) == nil {
				return
			}
		}
		os.Exit(1)
	}
	out, e := os.OpenFile("/dev/ttyS1", os.O_WRONLY, 0)
	if e != nil {
		os.Exit(23)
	}
	defer out.Close()
	if *phase == "deny" {
		emit(out, result)
		return
	}
	metadata, e := os.Lstat("/work/verified.json")
	if e != nil || !metadata.Mode().IsRegular() || metadata.Size() > 4096 || metadata.Mode()&0022 != 0 || metadata.Sys().(*syscall.Stat_t).Uid != 0 {
		os.Exit(25)
	}
	data, e := os.ReadFile("/work/verified.json")
	if e != nil {
		os.Exit(25)
	}
	var v ingest.Verified
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&v) != nil || decoder.Decode(new(any)) != io.EOF || !contracts.ValidDigest(v.ImageDigest) || !contracts.ValidDigest(v.ArchiveDigest) || !strings.HasPrefix(v.LayoutPath, "/work/oci-") || filepath.Clean(v.LayoutPath) != v.LayoutPath || strings.Contains(v.LayoutPath[len("/work/"):], "/") || v.Entries < 1 || v.Entries > j.Policy.Limits.Entries || v.ExpandedBytes < 0 || v.ExpandedBytes > j.Policy.Limits.ExpandedBytes {
		os.Exit(25)
	}
	if e = filepath.Walk(v.LayoutPath, func(_ string, st os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		if st.Mode()&0022 != 0 || st.Sys().(*syscall.Stat_t).Uid != 0 || !st.IsDir() && !st.Mode().IsRegular() {
			return ingest.ErrDenied
		}
		return nil
	}); e != nil {
		os.Exit(25)
	}
	result, e = ingest.Scan(context.Background(), "", "/scan-work", j, v)
	if e != nil {
		result.ImageDigest = ""
		result.Outcome = "denied"
	}
	emit(out, result)
}
func emit(out io.Writer, r contracts.ArtifactResult) {
	b, e := json.Marshal(r)
	if e != nil || len(b) > contracts.MaxBuildResultBytes {
		os.Exit(26)
	}
	if _, e = io.WriteString(out, "M07 "+string(b)+"\n"); e != nil {
		os.Exit(27)
	}
}
