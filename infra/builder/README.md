# Builder host assets — not provisioned

No VM image, libvirt definition, installer, firewall rule or enabled systemd service is shipped yet. Do not deploy a production builder from this directory. P1-M04 currently supplies the typed mTLS/lease core only.

See [provisioner implementation and open Linux gates](../../docs/implementation/build-provisioner.md). Production backend remains hard-disabled until the host-level quota, pinned-image, monotonic expiry, late-start fence, ownership and cleanup controls are implemented and proven on an approved Linux KVM host. Start with disconnected test guests, not real repositories.

Future reviewed host assets belong here: reproducible credential-free immutable image recipe, fixed backend configuration schema, host deadline/fence integration, separate guard service and explicit operator-approved installation/rollback runbook. Do not add privileged DinD or unisolated local builds as a fallback.
