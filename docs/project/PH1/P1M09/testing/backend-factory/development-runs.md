# Development runs retained; not acceptance

- Initial full `go test ./...` with TMPDIR unset failed the existing buildjob
  artifact workflow scenarios `success`, `resume`, `promotion-crash` and
  `service-restart`. `/tmp` was a 3.9 GiB tmpfs with about 1.1 GiB available,
  insufficient for the fixture's 2 GiB upload reservation. Moving temporary files
  to a sufficiently large filesystem passed the buildjob package. No production
  artifact capacity check was weakened.
- `software-long-tmp-failed.jsonl` and `race-long-tmp-failed.jsonl` retain the
  subsequent full/race failures using the long private TMPDIR under
  `/var/lib/orchestrator-builder/m09-tools/go-test-temp`. Unix socket fixture
  paths exceeded Linux's pathname limit and bind returned invalid argument.
- `/var/tmp/tap-m09` is private, short and on the larger filesystem. The recorded
  final `checks.json` uses this location; every check exited 0.
- `before-final-observer-*` logs passed before the final fixed daemon argument,
  data-root and parent-directory checks were added. They are retained as
  development provenance, not verification of those final changes.
- VM serial runs 1 and 2 passed the narrower identity diagnostic on superseded
  source. Run 3 adds actual daemon argument checks and the final source freeze.
  All VM disks were fresh images built from the never-booted trusted root tree,
  run with snapshot writes and no NIC. No guest-modified disk was mounted on
  management. Daemons were stopped and guests powered off by the fixture trap.
