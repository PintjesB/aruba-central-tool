# Configuration management roadmap

## Objective

Reduce configuration duplication and unnecessary scope overrides in New Central while preserving the intended effective configuration and network behavior. Prioritize workflows that save engineering time on existing customer deployments. Read-only analysis must remain useful even when some profile types are unqualified.

## Priority 0: reliable inputs

- [ ] Validate browser connection, automatic region discovery, transient credentials and read-only refresh on a real tenant.
- [ ] Qualify each module and its local, effective and Library views separately; distinguish empty, unsupported, incomplete, and forbidden responses.
- [ ] Resolve actual device membership (site, site collection and device group), configuration authority (New versus Classic), persona and supported model/firmware.
- [ ] Resolve exact configuration source and nearest applicable ancestor. Device groups are a separate inheritance path. Do not infer parentage from ordered scope lists.
- [ ] Establish profile schema, identity, cardinality (additive versus replacement), default semantics, applicability and references for each supported module. Read-only inference must not authorize writes.
- [ ] Preserve snapshots and compare changes within a verified tenant. Report incomplete scope and assignment coverage explicitly.

## Central-only retrieval boundary

**Current decision:** use only Aruba Central APIs, including its documented configuration, monitoring and troubleshooting endpoints. Do not introduce direct switch SSH, native AOS-CX REST, device credentials or connectivity requirements.

- [x] Verify retrieval of VLAN voice state, DHCPv4 and DHCPv6 snooping on a sampled switch (29/29 VLANs). Retain actual observed values and their sources; broader tenant coverage still requires validation.
- [x] Recognize valid empty IGMP/MLD routed-interface responses without treating them as Layer 2 snooping state.
- [ ] **Deferred: complete VLAN IGMP and MLD snooping retrieval through Central.** The tested Central command allowlist does not expose the snooping-specific commands, and supported multicast commands returned no routed-interface records. Configuration reads did not supply the missing fields. Revisit when Central exposes a suitable API, command or documented default-expansion mechanism.
- [ ] Track other unavailable configuration fields and module types during Central-only coverage work. Qualify each newly available source before using its values.

Show unknown effective/reference values as **Unavailable**, including settings omitted by every source. Keep omitted saved-local fields distinct from verified disabled values. Never infer a default, match, or safe override removal from missing evidence. Direct-device access remains outside the current scope; reconsider only if explicitly approved.

## Priority 1: consolidation advisor

Implemented: offline recommendations for C01/C02 (Global-match review), C03 (VLAN default review), C04/C08 (conflicting bodies), C05/C06 (exact repeated locals), C07 (exact Library reuse), and C10 (no observed assignments). The advisor shows captured higher-scope and device coverage, supports selection and exports non-executable previews. Captured site, collection and group ID correlations now support proposed target selection and observed recipient previews; unknown or ambiguous IDs are retained. Actual inheritance, complete membership and dependency safety, and all live write operations remain pending. C09 (Library identity-independent matches), C11 (repeated port settings), C13 (direct-device shadowing), and C15 (explicit VLAN and switch port-profile reference evidence) have read-only engineering review implementations. Engineering review also compares matching reusable switch port profiles and per-device visibility, previews exact port mappings, correlates group/site/collection/global shadowing where direct winning source and membership evidence agree, and includes observed references for duplicate Library identities. Semantic identity consolidation, port conversion and exhaustive reference coverage remain pending. C12, C14 and C16-C18 remain planned.

Each finding shows source scope, device function, profile identity, exact local and effective bodies, alternative/reference body, affected scopes and devices, dependencies, proposed action, blockers and confidence. Group repeated bodies without losing original locations. Offer filters for module, site, group, device function, action and risk. No writes from the advisor.

| ID | Scenario | Suggested action | Required evidence |
|---|---|---|---|
| C01 | Local device override matches applicable inherited configuration | Remove redundant override | Exact prospective inherited body and source, including intermediate and device-group precedence |
| C02 | Local site/group/collection override matches inherited configuration | Remove redundant override | All descendant devices retain intended effective settings |
| C03 | Local override differs only by omitted/default fields | Review possible normalization | Module-specific documented defaults and firmware/behavior evidence |
| C04 | Local override genuinely differs | Keep intentional exception or standardize with explicit approval | Side-by-side differences and affected device set |
| C05 | Identical local profiles exist at multiple devices | Promote to lowest common suitable scope, or assign Library profile to exact scopes; remove redundant locals | Membership, target support, exact consumers, no unintended propagation |
| C06 | Identical definitions repeat across sites/groups | Reuse or create Library profile and assign to appropriate scopes | Exact bodies, applicable persona(s), dependencies and assignments |
| C07 | Local profile exactly matches existing Library profile | Prefer reuse and assignment over another copy | Verified identity, exact body, assignment behavior and precedence |
| C08 | Same identity has multiple distinct bodies | Flag conflict; choose canonical profile and preserve approved exceptions | Per-variant comparison, source/consumer coverage and explicit intended changes |
| C09 | Library has duplicate content under different identities | Review consolidation of names/IDs | Module identity semantics, all references and assignment graph; never merge solely on body similarity |
| C10 | Library profile has no observed assignments | Review unused-profile candidate | Complete assignment and reverse-reference coverage; never infer unused from incomplete evidence |
| C11 | Multiple interfaces have equivalent settings | Recommend port profile/interface-profile reuse | Normalize only documented device-specific fields, preserve port identity, uplink/LAG, VLAN, PoE, security and topology dependencies |
| C12 | Settings are inconsistently applied across devices of the same purpose | Compare to approved reference or desired standard | Explicit target set and intentional exceptions |
| C13 | Local profile or assignment is shadowed by a closer scope | Review unnecessary assignment/override | Actual precedence, all affected devices, and future-use policy |
| C14 | Configuration exists but is not observed on intended devices | Investigate missing assignment, applicability or sync | Assignment/monitoring evidence; never assume configuration delivery |
| C15 | Referenced profile is missing or incompatible | Flag broken reference and recommend remediation | Qualified dependency graph and module-specific semantics |
| C16 | Profile is present but apparently unused on devices | Review orphaned configuration | Operational and reverse-reference evidence; lack of observation is not proof of disuse |
| C17 | Same profile name or VLAN ID has divergent definitions across functions | Review intended cross-function policy and conflicts | Function-specific schema and applicability; no automatic cross-persona merge |
| C18 | Changes introduce drift since previous snapshot | Explain changes and generate review/rollback evidence | Comparable snapshots, tenant identity and exact scope/profile changes |

## Priority 1: placement and Library advisor

Library is a reusable profile repository, not an application scope. A shared profile needs explicit scope/device-function assignment. Local profiles suit a unique scope or intentional exception. Prefer the narrowest placement that covers the intended recipients without adding consumers. Use reusable Library profiles when consistent policy must be assigned across scopes/functions, including provisioning of future devices.

| Configuration | Typical placement recommendation |
|---|---|
| Common Layer 2 VLAN definitions | Library with Global assignment if intended everywhere; otherwise assign only to relevant site/group/device scopes |
| Site-specific VLAN | Site or group local profile, or Library assignment if reused |
| Switch access/trunk port settings | Reusable switch port/interface profiles; keep actual interface mapping and unique port attributes local |
| WLAN SSIDs, roles, policy and AAA profiles | Library where module supports reuse and security policy is common; retain per-site or per-role exceptions |
| DNS/NTP/logging/SNMP settings | Shared profiles for standard infrastructure settings, with site-specific services or credentials reviewed separately |
| Switch/AP system settings | Reuse common supported settings; keep hostnames, unique addresses and per-device attributes local |
| QoS, ACL/policy, authentication and multicast settings | Reuse standard policy only after confirming compatibility, ordering and dependent resources |
| SVIs, routed interfaces, LAG membership, addressing, VRRP/active gateway | Generally topology-specific; protect device-unique attributes and only promote explicitly supported shared portions |

Do not assume all modules support every scope. In particular HPE's VLAN guidance recommends reusable Layer 2 VLANs in Library with Global assignment; some switch documentation limits creation of custom local VLANs at Global scope. Check actual supported contract before constructing a plan. Existing Library assignments replaced by a local override may have been unassigned, so deleting the local object alone may not restore the previous shared assignment.

## Priority 2: guided change planner

Laboratory-only initial VLAN write adapter implemented in `vlan_change.py`: exact device-local removal, higher-scope local creation, Library creation/reuse and assignment, fresh-plan approval digest, phased verification, persistent journal and guarded compensating rollback. Simulation tests cover successful paths, drift, SVI/unknown-field blocks, rollback and uncertain responses. Production qualification, browser integration and broader module/port/Library identity writes remain pending; no live writes were tested.

- [x] Select candidates individually or by exact repeated-profile group, preserving all observed source scopes.
- [x] Preview candidate destination scope membership from captured IDs, distinguishing intended, additional and unknown recipients; verified effective blast radius and protected-exception handling remain pending.
- [ ] Choose reuse existing Library profile, create Library profile plus assign, create supported local profile at a higher scope, or remove redundant override.
- [ ] Show ordered operations, before/expected-after configuration, reference changes and rollback journal. Block a plan when any prerequisite is unknown.
- [ ] Capture fresh evidence just before execution, detect drift and reject stale plans.
- [ ] Implement explicit approval, per-module write adapters, least-privilege authentication, idempotent operations, phased verification and failure handling.
- [ ] Create/reuse and verify target configuration before removing local definitions. Verify every affected device after changes, including operational checks where meaningful.
- [ ] Restore prior bodies and assignments on failure using validated rollback operations. Never claim rollback is guaranteed without proving the inverse operations.

No live write may be authorized by profile similarity, inferred identity, or a successful read alone. Start with the VLAN workflow; validate every subsequent write adapter independently. No automatic deletion of defaults, SVI/port/LAG dependencies, or unresolved objects.

## Priority 3: adjacent engineering workflows

- [ ] Bulk profile and scope assignment editor, device-group rename and membership change preview.
- [ ] NAC MAC identity/tag/role/VLAN assignment inspection and controlled bulk administration.
- [ ] Device/reference comparison, standards compliance, historical drift reports and private customer exports.
- [ ] Multi-customer workspaces with explicit tenant separation, credential entry in memory only, no persistent API credentials and no cross-tenant comparison by default.

## Vendor references

- [Configuration model and precedence](https://arubanetworking.hpe.com/techdocs/VSG/docs/002-central/central-020-config-model/)
- [Working with local profiles](https://developer.arubanetworks.com/new-central/docs/working-with-local-profiles)
- [Working with Library profiles](https://developer.arubanetworks.com/new-central/docs/working-with-library-profiles)
- [Configuration deployment models](https://arubanetworking.hpe.com/techdocs/new-central/content/cfg/get-start/get-start-cfg.htm)
- [VLAN profile deployment guidance](https://arubanetworking.hpe.com/techdocs/new-central/content/cfg/profiles/vlan-prof.htm)
- [AOS-CX configuration scope limitations](https://arubanetworking.hpe.com/techdocs/new-central-review/content/get-started/cx-cfg.htm)

## Decision-oriented UX acceptance criteria

Every engineering finding must expose the evidence, a useful next action, the affected objects and devices, an explicit choice where multiple alternatives exist, and the prerequisites for execution. Avoid presenting generic review categories as faults. Keep unknown counts and missing values distinct from zero and false. Raw payloads are secondary evidence.

- Duplicate Library profiles: separate each name's observed scope/function assignments, shared device deployments and distinct referencing objects; suggest a name to retain based on observed migration effort, allow a different selection, preview the other names' migration workload. Reference graph completeness and semantic interchangeability remain unverified.
- Device overrides: compare saved, effective and Global settings and applicable higher scopes; explain whether a local definition is a potential redundancy or an intentional difference. The default device override worklist shows redundant saved Global matches and likely redundant observed matches, independently of generic write-adapter support. Show genuine differences and local-only definitions in the separate All local definitions view. Redundancy relative to Global and removal readiness are distinct: flag differing applicable higher scopes and incomplete evidence before removal. Show explicit match/difference/unavailable counts, exclude VLAN identity and GET-only Layer 3 context from those setting counts, and disclose higher-scope exceptions. Keep unavailable fields separately expandable and never treat them as verified equal. Partial evidence cannot authorize removal; the existing executable change qualification remains unchanged.
- Port consolidation: show candidate mappings, existing profile matches and observed usage, visibility, dependency checks and a recommended next step.
- Scope precedence: show the applied definition, higher-scope alternative, affected devices and whether to review lower-scope redundancy or retain intentional settings.
- Library: distinguish assignment counts from observed shared deployments and referencing objects. Never infer unused from zero observations.
- Configuration and comparison: show actual values and provenance, affected devices, and direct navigation to the relevant engineering workflow. Continue validating the real browser against customer snapshots and prioritize decision clarity over additional raw tables.
