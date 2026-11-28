# Aruba Central Tool

## Repository layout

- `aruba_central/`: application package, collection and transport, configuration analysis, web UI, CLI implementations and pinned API catalog. Internal modules use package-relative imports.
- `tests/`: regression and browser tests.
- `.github/workflows/`: CI.
- Root Python files are compatibility launchers only. Prefer `python -m aruba_central` and the package diagnostic modules. Existing `python central_tool.py`, `coverage_diagnostics.py`, `live_collection_probe.py`, `probe_vlan.py` and `vlan_change.py` commands still work from a checkout. No installation or third-party runtime dependencies are required.


First milestone: read-only VLAN configuration consolidation discovery for New Central, including tenants with the Classic toggle where the APIs are available.

## Quick start

Python 3.11+; no third-party dependencies. Run from a trusted workstation. Create a Central-scoped Personal API client with read-only permissions (GreenLake > Manage Workspace > Personal API clients). For EU tenants, omit CENTRAL_BASE_URL to detect de1/de2/de3 automatically. If configured, the preferred region is tried first; only a 401 triggers EU fallback. Ambiguous or other failures stop the scan. For non-EU tenants, set the exact regional API URL. Use scan --region-file /path/outside/repo/region.txt to load and save the selected region locally (CENTRAL_BASE_URL takes precedence). This is a read-only inventory probe, not a tenant identity check. Never put credentials into Git or chat.

Linux/macOS:
```bash
export CENTRAL_BASE_URL=https://de1.api.central.arubanetworks.com
read -r -p "Client ID: " CENTRAL_CLIENT_ID; export CENTRAL_CLIENT_ID
read -r -s -p "Client secret: " CENTRAL_CLIENT_SECRET; export CENTRAL_CLIENT_SECRET; echo
python -m aruba_central scan --output snapshot.json
python -m aruba_central report snapshot.json --output report.json
unset CENTRAL_CLIENT_ID CENTRAL_CLIENT_SECRET
```

Alternatively set CENTRAL_ACCESS_TOKEN instead of the client ID and secret. For PowerShell, set the environment variables locally using a secure secret prompt. Both commands refuse to overwrite existing output. A scan writes raw profile and scope data locally, so treat the snapshot and report as confidential. The repository is public; do not commit customer data.

The scan discovers Global, site collections, sites, groups and device inventory, reads Library VLANs and shared assignments, and obtains committed local, effective and annotated effective VLAN views at discovered scopes for the selected switch persona (default ACCESS_SWITCH). The report compares full unannotated VLAN bodies and shows global deviations, exact duplicate local definitions, and potential redundant overrides. It does not assert that removal is safe. Array order, absent fields and explicit defaults are intentionally preserved. Unknown personas are listed separately. API failures are fatal rather than interpreted as empty configuration. Device-group reads may be restricted on dual-interface accounts; if so the scan stops.

## Review a saved snapshot

Run the report command again with a new output filename after upgrading. No API credentials or requests are required. The JSON includes a review entry for every local VLAN (even singletons), matching Global and Library content, per-device matching/missing/different coverage, and available effective annotations. The terminal displays anonymized aggregate counts. These are review suggestions, not migration plans. Exact equality does not prove equivalence; device coverage is limited to the scanned persona and does not authorize Global assignment.

### Default-aware review

The second-stage assessment distinguishes documented default candidates, explicit differences, multicast defaults requiring model/firmware validation, unresolved omissions, and the GET-only is-l3-vlan indicator. It does not rewrite profiles or treat omitted fields as proven equivalent. Verify actual SVI state and device behavior before migration. Library-only VLANs are reviewed at their existing scope, not automatically promoted globally. The terminal can display aggregate boolean values for allowlisted VLAN settings, but never names or customer identifiers.

## Device compatibility and dependency discovery

Use `python -m aruba_central inventory --region-file region.txt --output inventory.json` to discover all inventory entries (including APs, gateways and unknown personas). Use `python -m aruba_central scan-all --region-file region.txt --output all.json` to automatically scan every discovered qualified switch persona in one file. Use `--persona ACCESS_SWITCH` with `report` or `dependencies` to select a view from that file when multiple personas are present. Switch VLAN scanning currently supports ACCESS_SWITCH, AGG_SWITCH and CORE_SWITCH; other configuration adapters are not qualified. Known firmware defaults are resolved by a documented model/release ruleset; unlisted combinations remain unknown rather than inheriting another model's defaults.

Use `python -m aruba_central dependencies snapshot.json --output dependencies.json` with credentials to probe the dependency modules of a saved scan. Empty responses, permission failures and rejected requests are distinct; none proves a feature is unsupported. Then run `python -m aruba_central report snapshot.json --dependencies dependencies.json --output report.json` offline. Raw inventory and snapshots stay private.

## Unified tenant audit

Run `python -m aruba_central audit --region-file region.txt --output audit.json` to discover inventory, scan all qualified switch personas, probe dependencies and generate per-persona reviews in one read-only operation. The audit collects fresh configuration and dependencies in the same run to avoid combining stale or different-tenant snapshots. The output bundles the inventory, configuration snapshots, dependency evidence and reports. Unqualified device functions remain explicitly listed, and the bundle is never an executable migration plan.

### VLAN reference and monitoring evidence

The audit probes interface profiles, roles and port channels in addition to the original dependency modules. It indexes explicitly VLAN-shaped configuration fields, keeping wildcard, unknown and ambiguous expressions unresolved. Candidate paths and values remain in the private report; this is not a complete dependency graph. The audit also attempts the documented switch VLAN monitoring endpoint using the discovered inventory serial or stack identity. Responses are saved as evidence; schema and completeness must be validated before deriving operational equivalence. No profile is marked migration eligible.

### Offline audit comparison and reference preview

Run `python -m aruba_central review-audit audit.json --previous earlier-audit.json --output review.json` to regenerate the review and compare two captures without credentials or network requests. Omit `--previous` to review just one capture. Match scopes by ID and compare exact local, effective and Library bodies. The private report includes before/reference field differences and blockers per profile. Reference bodies are not predictions of actual post-change inheritance and no preview is executable. Region and Global scope checks are not independent proof of tenant identity; compare only captures from the same tenant.

### Inheritance evidence

Offline reference previews include observed Library assignments matching the VLAN endpoint, numeric instance and persona. They do not infer intermediate scope precedence or guarantee that deleting a local profile restores a Library assignment. Historical local removals include effective field differences and comparisons of available monitoring fields; exact or default-only differences are not proof of operational equivalence.

## Broader configuration audit (experimental)

Run `python -m aruba_central config-audit --region-file region.txt --output config-audit.json` to discover the device functions and probe documented profile modules using committed local and annotated effective views. An optional `--persona ACCESS_SWITCH` limits the run. The catalog covers switch, AP, gateway and bridge candidate modules; unsupported requests, unknown shapes, duplicate profile identities and contradictory annotations are recorded as unqualified. Ethernet interface configuration is device-scoped. Profile keys and applicable personas are explicit documented adapters, not a universal API catalog. Global matches/differences are comparison evidence, not proof of a specific ancestor or of redundant configuration. Raw responses and per-field values remain private; the terminal shows counts. This audit is read-only and does not replace the VLAN dependency audit.

### Offline configuration browser

Run `python -m aruba_central review-config config-audit.json --output review.html` and open the generated HTML locally. The dashboard includes coverage and finding counters, color-coded status, quick views, device function/module/scope/status filters, searchable and sortable paginated findings, side-by-side field differences, raw evidence and filtered CSV export. The offline review reparses saved raw responses using current adapters; explicitly zero metadata-only local responses can be qualified without new API requests. Ambiguous nonempty responses remain unresolved. Unqualified scopes are displayed explicitly, and the terminal reports anonymous response shapes for further adapter qualification. No API calls, credentials, server or external assets are needed. Both the input and HTML report contain confidential configuration evidence; keep them outside the repository and do not publish or upload them.

### Local configuration workspace

Run `python -m aruba_central app --directory <private-audit-directory>` to open a loopback-only browser application. It lists saved configuration audit snapshots, opens the existing explorer, and compares two devices of the same persona within one snapshot. Device comparisons exclude infrastructure by default; explicitly select a module to include it. Exact differences do not prove behavioral equivalence.

Use a separate directory per customer. Existing workspaces require matching region, Global scope identity and common observed device serials before scoped collection and publication. These continuity checks are not authoritative tenant identification. Enter client ID, client secret and region directly in the browser and select Connect and refresh. Credentials and access tokens are held in process memory only for the audit and are not deliberately persisted, logged, or returned to the browser. The application cannot control browser password managers, OS paging or crash dumps; decline save prompts. For legacy automation, environment credentials with `--enable-refresh --region-file <region-file>` remain supported. Module coverage lists fully qualified modules first, distinguishes partial from unqualified scopes, and links to evidence. No scope is authorized for writes. Refresh creates a new private audit file; only one refresh can run at a time. The server binds to 127.0.0.1 on a random port, uses a random session URL, validates Host, refresh Origin/fetch metadata and a separate anti-CSRF form token, disables caching and framing, and does not log request URLs. Keep the local session URL private. Press Ctrl+C to stop. No dependencies or database are required.

### Deep catalog collection

The browser's Connect and refresh form defaults to Deep catalog. This adds committed and effective unfiltered reads at every discovered scope for documented profile collections without a qualified adapter, including modules not observed in assignments or Global configuration. Optimized Deep collection retains all collection-level reads and uses two representative individual reads for identical inherited, shared or default device profile bodies and annotations. A mismatch or failed verification expands the group. Exhaustive individual verification remains available (`--exhaustive-details` together with `--deep-catalog`). Fast catalog (`--targeted-catalog`) retains the structured scope reads, but expands supplemental unfiltered scope surveys only when current assignments, scoped data, Library or Global responses indicate settings. Unobserved supplemental device-local configuration can be missed in Fast mode; use full Deep collection for comprehensive discovery. Standard collection remains available for faster refreshes. For command-line audits, add `--deep-catalog` to `config-audit`; for environment-credential workspace refreshes, add it to `app`. Large tenants may require substantially longer refreshes. The terminal estimates additional requests before pagination, and Coverage distinguishes attempted scope surveys from count-confirmed responses. A rejected or unqualified read is not evidence of absence. Deep collection supports checkpoint recovery for qualified structured scope pairs, Library collections, raw catalog collections and keyed profile details. It does not qualify new write adapters or cover every keyed or specialized API operation.

### Additional module qualification and Library inventory

New captures retry ambiguous committed local responses with an unfiltered annotated committed view. Recovery requires complete count evidence and explicit non-inherited LOCAL or SHARED annotations on every returned object; conflicting or bare empty responses remain unqualified. Shared Library profiles are read once per applicable non-device-only module, with a separate assignment capture. Central NAC authentication profiles use the default tenant-level query, not per-device or per-persona queries. Library records and assignment responses are review evidence, not proof of assignment completeness or write authorization.

### Tenant-driven profile type discovery

The extended catalog adds DNS, NTP, SNMP, SNMP traps, logging, system information, MAC authentication, QoS queues, multicast membership, DHCP pools and gateway system/STP profiles, plus authentication servers. Applicability is a candidate adapter until live views qualify. Configuration assignments and the vendor SDK's read-only scope-maps evidence are captured once per audit to discover profile types and explicitly observed device functions. Missing or rejected scope-map responses remain unknown; observed modules without an identity adapter are reported separately, never queried using guessed identifiers. This catalog is not exhaustive. See the [PyCentral scope-map implementation](https://github.com/aruba/pycentral/blob/v2/pycentral/scopes/scope_maps.py) and [HPE configuration API reference](https://developer.arubanetworks.com/new-central-config/reference/).

### Unadapted profile evidence and Library comparison

When the observed assignment or scope-map inventories identify a module without a dedicated adapter, the audit attempts read-only Library and annotated committed/effective queries at the observed source scopes. Scope IDs, function selectors and module names are validated and repeated source queries are deduplicated. Raw evidence is available under Module coverage, explicitly unqualified and excluded from migration candidates. The Library browser also joins exact observed assignment identities and compares qualified local bodies of matching identities; absent assignments do not prove a profile is unused. All values remain in private local snapshots.

## Development roadmap

See [ROADMAP.md](ROADMAP.md) for the configuration consolidation workflows, Library selection criteria, safety gates and delivery order.

### Audit progress and performance

The local workspace shows authentication/discovery, scoped configuration, Library, additional profile types and snapshot publication progress. It polls only the loopback server once per second while an audit is running, refreshes the snapshot list on completion, and displays sanitized failures. Progress counts describe the current phase, not an estimated overall completion time.

Scoped reads across modules within a persona, Library collections and additional profile types start with twelve concurrent read workers. At phase boundaries the collector may increase this budget to at most twenty-four based on successful GET latency, while retaining the shared nine-request-per-second limit. Direct Central HTTPS GET connections are reused per worker when supported; proxies and non-GET requests retain standard transport. Throttling causes shared cooldown and gradual rate recovery. OAuth token renewal is serialized; HTTP 429 retries share a cooldown across workers. Scope review occurs after capture so the Global baseline is available independently of request completion order. No modules or applicable scopes are skipped for speed. Actual latency and throughput depend on Central and its rate limits; validate against a live capture.

### Saved standards and exceptions

From Standards compliance, choose an approved baseline snapshot, reference device, module or all standard modules, and target scope. Run the assessment and save a named local version. The version pins the original snapshot checksum and module set; keep that snapshot in the private workspace. Select the saved version and a newer current snapshot to reassess it. Confirm same-tenant identity for historical comparisons. Use one workspace directory per customer.

Open a device result to approve an exact, complete observed profile deviation with a reason and expiry date. Missing reads cannot be approved. An approval applies only to the same standard version, device serial and exact before/after field values (or complete profile presence deviations). Legacy whole-profile approvals remain supported. Changed values or expiry require review again. Exception history preserves approvals and reasoned revocations; expired, revoked and currently unobserved approvals remain visible. The files contain private customer configuration: keep them with the audit snapshots and out of source control. They are local review records, not centrally authenticated approvals.

Bulk consolidation previews summarize selected proposals, source and destination recipients, scope/Library overlaps and preparation, verification and cleanup phases. Resolve overlaps and select destinations before export. Duplicate Library migration previews show assignment and reference worklists plus the retained profile's visibility for affected devices. These are review-only plans, not executable API operations.

### Interrupted collection recovery

The browser offers a new resumable collection, a fresh collection without checkpoints, or an eligible interrupted collection. Select the same collection depth and enter credentials again to resume. For CLI use, add `--checkpoint <private-path.db>` to `config-audit`, then repeat with `--resume` and a new output filename if interrupted. Checkpoint files contain private customer configuration, never credentials. Recovery is limited to 24 hours and checks region, inventory identities, firmware, scopes, membership, and the collection catalog. Failed or unqualified reads are retried; inventory, operational monitoring and configuration health are always collected live. Completed checkpoints are sealed after snapshot publication. Keep checkpoint files private and remove them manually when no longer needed.

Recovered evidence may have mixed capture times. Such captures cannot qualify fresh remediation verification. They are suitable only for inspection with the stated evidence limits.

### Engineering evidence workflows

- **Configuration sources:** select a device, module and effective profile to compare saved and effective definitions through the scope chain and inspect Library assignment observations. A matching body alone does not prove the winning source.
- **Library assignments:** filter captured assignment tuples and inspect known recipients, uncertain membership, effective visibility and observed overlaps. Overlap may be intentional; it does not establish a policy conflict.
- **Port consolidation:** compare saved and effective per-port settings, candidate shared fields and fields to retain locally before considering a reusable profile. No executable conversion is generated.
- **Policy variants:** group same-identity effective configuration bodies within one device function and compare device populations and differing fields. The largest group is not automatically the correct standard.
- **Policy rule review:** compare the documented default security-policy rule subset (explicit ordered RULE_ANY with ADDRESS_ANY or ADDRESS_ROLE). Show equal or broader earlier match candidates and different action bodies; preserve unknown rules. Role ACLs also compare ordered literal IPv4/IPv6 destinations within the same explicit source role and VRF, retaining action and counter-setting differences. Unsupported predicates remain unknown. Inspect captured policy-group order and same-context target visibility; cross-policy overlap does not establish resultant behavior.
- **Configuration assessment:** open the consolidated coverage, optimization, policy and recovery worklists; export a private assessment report. Counts can overlap and are not a health score.
- **Remediation verification:** compare a prior qualified override candidate or duplicate Library group with a strictly newer same-tenant capture. Export prior bodies and observed assignments for rollback review, not executable restoration.
- **Compliance trends:** assess up to 20 saved captures against one frozen standard using approvals effective at the capture time. Baseline-driven templates select modules, and optional field rules select exact captured paths.

- **NAC identities:** inspect MAC registration pagination and identity duplicates, static tags, tenant-level authentication profiles, identity stores and authorization policies. Review explicit conditional RADIUS attributes, matching tag condition values and switch VLAN visibility. These are configuration observations, not simulated authentication outcomes. Named MPSK secrets are excluded.

All these browser workflows are read-only with respect to Central. Complete reference coverage, semantic ACL overlap, operational behavior and production write qualification remain separate tasks.

### Consolidation advisor

Open Consolidation advisor for any saved configuration audit. It groups qualified reusable local bodies and recommends review of Global-matching overrides, exact repeated locals, existing Library reuse, conflicting definitions, VLAN default differences and possible Library placement. It also flags profiles with no observed assignments when assignment evidence exists. Inspect captured device and higher-scope coverage, select recommendations and export a private, non-executable change preview. The preview includes observed dependency evidence and sequences selected prerequisites before consumers, with reverse cleanup review and cycle detection. Device-specific system settings and topology objects are excluded from generic promotion. All recommendations are blocked from automatic application pending inheritance, target support, dependency and rollback validation; the application performs no configuration writes.

### Laboratory VLAN change engine

The standalone `vlan_change.py` implements the first **laboratory-only** write adapter. It is not exposed as a production Apply button. Do not use it on customer or production tenants until the adapter is qualified against a disposable lab tenant and operational rollback is proven.

Create a private plan from live evidence: `python -m aruba_central.vlan_change plan --mode remove --persona ACCESS_SWITCH --vlan <id> --source <device-scope-id> --output <private-plan.json>`. For repeated exact local VLANs use `--mode promote` or `--mode library`, repeat `--source`, and specify `--target <scope-id>`. The latter creates/reuses a shared VLAN and assigns it at the selected higher scope. The source set must exactly equal the observed destination recipients. Source device membership, exact committed/effective bodies, annotated source evidence, SVI exclusion, and operational VLAN fields are required. Only a restricted simple VLAN schema is supported; conflicting defaults, existing target assignments and unknown fields block the plan. No implicit Global local VLAN creation.

To qualify in an isolated lab only, review the private plan and its SHA256, then run `python -m aruba_central.vlan_change apply <private-plan.json> --approve <sha256> --lab-only --journal <private-journal.jsonl>`. Credentials can be supplied by prompt (secret masked) or existing environment variables; they are not saved. The plan is regenerated from live evidence before any write. Creates and assignments precede source deletes. Each acknowledged operation is journaled, read back and compared with the expected direct state, full device effective VLAN bodies and captured source monitoring fields. Rollback reverses known acknowledged writes only when direct state still matches the expected transition. Uncertain responses or external drift stop for manual recovery; writes are never automatically retried. A completed verification is not proof of uninterrupted traffic, hardware equivalence, or production qualification. Journals contain confidential config; use a private directory.

Contracts: [create VLAN](https://developer.arubanetworks.com/new-central-config/reference/createlayer2vlanl2vlanbyid), [delete VLAN](https://developer.arubanetworks.com/new-central-config/reference/deletelayer2vlanl2vlanbyid), [Library assignment and unassignment](https://developer.arubanetworks.com/new-central/docs/working-with-library-profiles), [inheritance](https://arubanetworking.hpe.com/techdocs/VSG/docs/002-central/central-020-config-model/). Simulated transaction tests are not live API qualification.

### Workspace navigation

The browser workspace opens on an overview of the selected audit. Use the sidebar to switch between Consolidation, Engineering review, Configuration, Inventory, Library, Compare and Coverage. The selected snapshot is preserved in navigation links. Consolidation is task-first, with grouped recommendations, filters, pagination, a side inspector, a selection bar and non-executable preview export. Engineering findings have separate views for repeated port settings, shadowed configuration, duplicate Library profiles, unresolved reference evidence and observed references. Configuration, Library and Compare show compact tables with structured details and optional raw evidence. Coverage is a separate diagnostic view. The original full evidence report and CSV export remain available from Configuration. Theme changes affect the current page only. All assets are local, and the browser remains read-only.

### Operational VLAN evidence

New configuration audits also collect best-effort switch VLAN monitoring using discovered switch identities and the existing read-only monitoring query. The device overrides and consolidation inspectors distinguish saved and effective configuration from observed VLAN name, monitoring status, and tagged/untagged port membership. Older snapshots display monitoring as not collected. Monitoring failures do not invalidate the configuration capture. Reported VLAN status is not the configured enable field; neither omitted settings nor observed monitoring status establishes multicast behavior or migration safety. Refresh once to collect monitoring evidence.

## Safety boundary

No configuration mutation API calls exist yet. Only OAuth token issuance uses POST. Candidate findings are not executable plans. The API is v1alpha1 and real tenant response shapes, group access, annotation semantics, and Classic/New configuration authority must be validated before enabling writes. Scope IDs are strings, not floating-point numbers.

Next: validate live fixtures privately, resolve actual profile source/override semantics, map dependencies and effective device coverage, then add a dry-run promotion planner and separately gated apply/recovery.

## References

- [Authentication](https://developer.arubanetworks.com/new-central/docs/generating-and-managing-access-tokens)
- [Scope IDs](https://developer.arubanetworks.com/new-central/docs/how-to-get-scope-ids)
- [Local profiles](https://developer.arubanetworks.com/new-central/docs/working-with-local-profiles)
- [Library profiles](https://developer.arubanetworks.com/new-central/docs/working-with-library-profiles)
- [VLAN reads](https://developer.arubanetworks.com/new-central-config/reference/readlayer2vlan)
- [Device inventory](https://developer.arubanetworks.com/new-central/reference/getdeviceinventoryv1)
- [Device groups](https://developer.arubanetworks.com/new-central-config/reference/getdevicegroupsv1)

Run unit tests: `python -m unittest discover -s tests -v`.

## Live collection qualification

After a fresh Deep catalog refresh, run `python -m aruba_central.coverage_diagnostics --directory <private-workspace>` to print aggregate collection diagnostics for the latest snapshot. Optionally select a snapshot filename with `--snapshot`. No credentials or network calls are needed. The export contains allowlisted vendor endpoint templates, statuses, HTTP outcomes and aggregate counts, not device serials, names, scope identifiers, MAC addresses or profile contents. Review counts for customer confidentiality before sharing. A successful response does not prove completeness. Never upload the underlying private snapshot.

### Focused live validation without a full Deep collection

Use `python -m aruba_central.live_collection_probe --directory <private-workspace>` to sample current Ethernet interface, SNMP and network group collection contracts and keyed detail responses. The tool uses the latest snapshot's region, rechecks inventory and scope continuity, and prompts for credentials if they are not already available in the environment. Optional repeatable `--module` selects supported modules; `--sample` sets a limit of 1 to 4 devices per function and identities per view. Output contains aggregate read statuses, counts and HTTP errors only. It does not replace the saved snapshot or establish complete coverage. Review the counts before sharing.

### Performance qualification

To measure local processing on an existing saved capture, run `python -m aruba_central.local_benchmark --directory <private-workspace> --repeat 3 --output <new-json-file>`. Optionally specify `--snapshot <filename>` to compare the same capture across revisions. This reports per-stage wall and CPU timings, cache-hit timings and aggregate counts, without contacting Central, exporting customer identifiers or modifying the snapshot. OS filesystem caching is not disabled; compare on the same machine and workload. Add `--ui` to measure optimization worklists, scope health, individual and grouped configuration search, and server-side rendering of the assessment, health, customer report and one captured device review. The search uses a fixed synthetic term (`vlan`); only aggregate counts and rendered byte sizes are reported. Browser interaction latency is not measured. This is separate from live collection acceptance.


Track implementation and live acceptance in [issue #170](https://github.com/PintjesB/aruba-central-tool/issues/170). Use `python -m aruba_central.live_collection_probe --directory <private-workspace> --performance --sample 1 --output <new-json-file>` to compare complete annotated typed and unfiltered reads, test page limits 100 and 500, and check immediate conditional GET behavior. The bounded probe does not reuse configuration across audits, qualify a module's complete applicability, or authorize changes. A 304 only establishes immediate conditional behavior for the same selector; inheritance and deletion invalidation remain unqualified. No comprehensive multi-scope configuration export has been identified in the current API catalog.

After a fresh Deep collection, use `python -m aruba_central.coverage_diagnostics --directory <private-workspace> --output <new-json-file>`. Both output commands refuse to overwrite existing files. The workspace displays overall estimated progress, a read-only preview of completed structured modules during collection, and collection performance history for the five latest saved snapshots. The preview is not a complete snapshot and is unavailable to change planning. Compact snapshots retain the existing JSON schema; an optional small fingerprint-bound performance sidecar accelerates historical comparisons. The original capture remains authoritative. All request reduction and throughput claims require comparable live acceptance.

### Tenant snapshot names

Optionally enter a tenant/customer name in the connection form. New snapshots include a filesystem-safe version of that label in the filename, and the exact display label in private snapshot metadata. The label is operator supplied (not an authenticated tenant identifier), is not included in anonymous diagnostics, and does not replace the existing workspace identity guard. Previously saved snapshots are unchanged. Keep one workspace directory per customer.


### Validate an exported consolidation preview offline

New consolidation preview exports include a selection manifest bound to the exact
saved snapshot file in the local workspace. To independently re-derive the selected
proposals, recipient counts, destination choices and review export gates:

```shell
python -m aruba_central.review_manifest --directory <private-workspace> --preview <consolidation-preview.json>
```

Use the original, unchanged snapshot in the same workspace. Older exports
without a manifest must be exported again. The validator ignores client-provided
proposal bodies and bulk summaries; it reconstructs the selection from the
capture. A passing result qualifies the local review selection only, not the
contents of every exported field, live state, authorization, deployment,
or permission to execute. Do not transfer these private exports to the public
repository.


### Measure local browser responsiveness (optional)

The regular local benchmark measures server-side analysis and HTML generation.
To additionally measure real browser navigation, DOM size and on-demand
evidence loading, install the optional Playwright package in your local
Python environment, then run:

```shell
python -m aruba_central.browser_benchmark --directory <private-workspace> --repeat 3 --output <new-report.json>
```

Use `--browser <existing Chromium, Chrome or Edge executable>` to use a local
browser rather than installing the Playwright Chromium binary. Otherwise,
install that binary with `python -m playwright install chromium` if needed.
The benchmark uses a temporary loopback workspace server, blocks external
page requests, does not contact Central and reports aggregate measurements only.
Navigation timings include server work, HTTP, DOM initialization and two
animation frames, not measured visual paint or production deployment behavior.
The reviewed snapshot is warm; the first visit may still populate other caches.

### Combined offline qualification

When sharing the local performance, keyed qualification and browser benchmarks together, run one command against a saved capture. The suite chooses the snapshot once, verifies that the file has not changed between stages, and writes one aggregate JSON file only after the reports succeed. It also independently validates advertised individual consolidation review choices (up to 200, with explicit coverage and rejection counts) and summarizes observed destination impact. This is not deployment or write qualification. It makes no Central API requests. The individual report commands remain available. Playwright and an available Chromium-based browser are required.

```powershell
python -m aruba_central.qualification_suite --directory "$env:USERPROFILE\.aruba-central-tool" --repeat 3 --browser "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe" --output "$env:USERPROFILE\Downloads\aruba-qualification-suite-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
```
