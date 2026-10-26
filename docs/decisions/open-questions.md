# Open questions and release blockers

| ID | Decision needed / default | Owner / gate |
|---|---|---|
| Q01 | Linux distribution, KVM availability and hardware budget; default LTS + KVM | Operator / before P1-M01 integration |
| Q02 | Is TOTP mandatory before first production deployment? If yes advance PH3 MFA tasks | Product/security owner / PH1 release |
| Q03 | Two owned registrable domains or local hosts/CA only? Default separate portal/app domains | Operator / PH2 production |
| Q04 | Private Git needed PH1? Default public approved HTTPS only until broker tests | Product/security / before credentials enabled |
| Q05 | Exact rootless network driver and cgroup/MAC/quota capabilities | Platform owner / isolation proof, release blocking |
| Q06 | Initial resource budgets, build duration and max app count | Operator / benchmark before PH1 release |
| Q07 | Registry/scanner tools and vulnerability thresholds | Security / PH1 scan gate; default block known exploited and fixable critical findings |
| Q08 | Supported browsers and third-party-cookie fallback acceptance | Product / PH2 browser gate |
| Q09 | Backup destination, retention, key escrow and tested RPO/RTO | Operator / first persistent production app |
| Q10 | Whether apps are mutually distrusting hostile tenants | Security / choose per-app VM before admitting such tenancy |
| Q11 | Custom domains, ACME provider and ownership proof | Operator / route feature activation |
| Q12 | Audit retention/privacy rules and external immutable destination | Operator / production logging approval |
| Q13 | Language/toolchain/library versions | Implementer / verify maintenance then lock; no existing stack found |
| Q14 | Private on-prem dependencies | Default unsupported; design isolated mirror before any internal-range exception |
| Q15 | Approved no-network/offline mode for confidential source | Security/data owner / before sensitive source builds |

Proposed defaults let implementation of pure contracts/tests proceed, not bypass blocked integration gates. Record answers as ADR amendments with test impact. Critical Q05 failing means use a validated different network mechanism/per-app VMs or stop; never silently loosen isolation.
