# Proposed project structure

No source files are created by this plan. After approval, keep repository's existing `plans/` untouched until its ownership is clarified; copy these docs into requested `docs/` only outside Plan mode and with authorization.

```text
cmd/{api,controller,runtime-agent,build-runner,vm-provisioner,ingress-relay,artifact-ingest}/
internal/{auth,acl,audit,api,jobs,policy,gitfetch,build,registry,runtime,proxy,secrets,volumes,storage}/
api/openapi.yaml
api/agent.schema.json
api/deployment.schema.json
web/src/{auth,layout,apps,deployments,admin,api}/
migrations/
policy/{compose,runtime,egress,seccomp}/
infra/{management,runtime,builder,gateway,registry}/
tests/{unit,contract,integration,security,browser,fixtures}/
tools/{dev,diagnostics,restore}/
docs/
```

Start as one Go module with separate binaries, not many independently versioned microservices. API and controller may initially be one process with clear packages; provisioner, agent, builder and relay remain distinct identities/security domains. React frontend is a separate build artifact served without Node in production. Choose maintained versions after checking current support; pin modules, toolchains, container digests and VM images.

Dependency direction: domain/spec → policy/storage → application services → adapters/handlers. Engine adapters accept validated types, not untyped JSON. Policy packages must not import frontend code. Protocol schemas have golden fixtures shared by independent implementations/tests; agent revalidates without trusting controller success.

Conventions: task IDs in commits/tests; structured errors; context deadlines; argv execution; no generic exec helper accepting shell strings; log fields classify secret vs public; migrations numbered and checksummed. Every task supplies changed-file list, test evidence, assumptions and unresolved issues for handoff.
