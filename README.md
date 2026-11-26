# Aruba Central Tool

First milestone: read-only VLAN configuration consolidation discovery for New Central, including tenants with the Classic toggle where the APIs are available.

## Quick start

Python 3.11+; no third-party dependencies. Run from a trusted workstation. Create a Central-scoped Personal API client with read-only permissions (GreenLake > Manage Workspace > Personal API clients). For EU tenants, omit CENTRAL_BASE_URL to detect de1/de2/de3 automatically. If configured, the preferred region is tried first; only a 401 triggers EU fallback. Ambiguous or other failures stop the scan. For non-EU tenants, set the exact regional API URL. Use scan --region-file /path/outside/repo/region.txt to load and save the selected region locally (CENTRAL_BASE_URL takes precedence). This is a read-only inventory probe, not a tenant identity check. Never put credentials into Git or chat.

Linux/macOS:
```bash
export CENTRAL_BASE_URL=https://de1.api.central.arubanetworks.com
read -r -p "Client ID: " CENTRAL_CLIENT_ID; export CENTRAL_CLIENT_ID
read -r -s -p "Client secret: " CENTRAL_CLIENT_SECRET; export CENTRAL_CLIENT_SECRET; echo
python central_tool.py scan --output snapshot.json
python central_tool.py report snapshot.json --output report.json
unset CENTRAL_CLIENT_ID CENTRAL_CLIENT_SECRET
```

Alternatively set CENTRAL_ACCESS_TOKEN instead of the client ID and secret. For PowerShell, set the environment variables locally using a secure secret prompt. Both commands refuse to overwrite existing output. A scan writes raw profile and scope data locally, so treat the snapshot and report as confidential. The repository is public; do not commit customer data.

The scan discovers Global, site collections, sites, groups and device inventory, reads Library VLANs and shared assignments, and obtains committed local, effective and annotated effective VLAN views at discovered scopes for the selected switch persona (default ACCESS_SWITCH). The report compares full unannotated VLAN bodies and shows global deviations, exact duplicate local definitions, and potential redundant overrides. It does not assert that removal is safe. Array order, absent fields and explicit defaults are intentionally preserved. Unknown personas are listed separately. API failures are fatal rather than interpreted as empty configuration. Device-group reads may be restricted on dual-interface accounts; if so the scan stops.

## Review a saved snapshot

Run the report command again with a new output filename after upgrading. No API credentials or requests are required. The JSON includes a review entry for every local VLAN (even singletons), matching Global and Library content, per-device matching/missing/different coverage, and available effective annotations. The terminal displays anonymized aggregate counts. These are review suggestions, not migration plans. Exact equality does not prove equivalence; device coverage is limited to the scanned persona and does not authorize Global assignment.

### Default-aware review

The second-stage assessment distinguishes documented default candidates, explicit differences, multicast defaults requiring model/firmware validation, unresolved omissions, and the GET-only is-l3-vlan indicator. It does not rewrite profiles or treat omitted fields as proven equivalent. Verify actual SVI state and device behavior before migration. Library-only VLANs are reviewed at their existing scope, not automatically promoted globally. The terminal can display aggregate boolean values for allowlisted VLAN settings, but never names or customer identifiers.

## Device compatibility and dependency discovery

Use `python central_tool.py inventory --region-file region.txt --output inventory.json` to discover all inventory entries (including APs, gateways and unknown personas). Use `python central_tool.py scan-all --region-file region.txt --output all.json` to automatically scan every discovered qualified switch persona in one file. Use `--persona ACCESS_SWITCH` with `report` or `dependencies` to select a view from that file when multiple personas are present. Switch VLAN scanning currently supports ACCESS_SWITCH, AGG_SWITCH and CORE_SWITCH; other configuration adapters are not qualified. Known firmware defaults are resolved by a documented model/release ruleset; unlisted combinations remain unknown rather than inheriting another model's defaults.

Use `python central_tool.py dependencies snapshot.json --output dependencies.json` with credentials to probe the dependency modules of a saved scan. Empty responses, permission failures and rejected requests are distinct; none proves a feature is unsupported. Then run `python central_tool.py report snapshot.json --dependencies dependencies.json --output report.json` offline. Raw inventory and snapshots stay private.

## Unified tenant audit

Run `python central_tool.py audit --region-file region.txt --output audit.json` to discover inventory, scan all qualified switch personas, probe dependencies and generate per-persona reviews in one read-only operation. The audit collects fresh configuration and dependencies in the same run to avoid combining stale or different-tenant snapshots. The output bundles the inventory, configuration snapshots, dependency evidence and reports. Unqualified device functions remain explicitly listed, and the bundle is never an executable migration plan.

### VLAN reference and monitoring evidence

The audit probes interface profiles, roles and port channels in addition to the original dependency modules. It indexes explicitly VLAN-shaped configuration fields, keeping wildcard, unknown and ambiguous expressions unresolved. Candidate paths and values remain in the private report; this is not a complete dependency graph. The audit also attempts the documented switch VLAN monitoring endpoint using the discovered inventory serial or stack identity. Responses are saved as evidence; schema and completeness must be validated before deriving operational equivalence. No profile is marked migration eligible.

### Offline audit comparison and reference preview

Run `python central_tool.py review-audit audit.json --previous earlier-audit.json --output review.json` to regenerate the review and compare two captures without credentials or network requests. Omit `--previous` to review just one capture. Match scopes by ID and compare exact local, effective and Library bodies. The private report includes before/reference field differences and blockers per profile. Reference bodies are not predictions of actual post-change inheritance and no preview is executable. Region and Global scope checks are not independent proof of tenant identity; compare only captures from the same tenant.

### Inheritance evidence

Offline reference previews include observed Library assignments matching the VLAN endpoint, numeric instance and persona. They do not infer intermediate scope precedence or guarantee that deleting a local profile restores a Library assignment. Historical local removals include effective field differences and comparisons of available monitoring fields; exact or default-only differences are not proof of operational equivalence.

## Broader configuration audit (experimental)

Run `python central_tool.py config-audit --region-file region.txt --output config-audit.json` to discover the device functions and probe documented profile modules using committed local and annotated effective views. An optional `--persona ACCESS_SWITCH` limits the run. The catalog covers switch, AP, gateway and bridge candidate modules; unsupported requests, unknown shapes, duplicate profile identities and contradictory annotations are recorded as unqualified. Ethernet interface configuration is device-scoped. Profile keys and applicable personas are explicit documented adapters, not a universal API catalog. Global matches/differences are comparison evidence, not proof of a specific ancestor or of redundant configuration. Raw responses and per-field values remain private; the terminal shows counts. This audit is read-only and does not replace the VLAN dependency audit.

### Offline configuration browser

Run `python central_tool.py review-config config-audit.json --output review.html` and open the generated HTML locally. The dashboard includes coverage and finding counters, color-coded status, quick views, device function/module/scope/status filters, searchable and sortable paginated findings, side-by-side field differences, raw evidence and filtered CSV export. The offline review reparses saved raw responses using current adapters; explicitly zero metadata-only local responses can be qualified without new API requests. Ambiguous nonempty responses remain unresolved. Unqualified scopes are displayed explicitly, and the terminal reports anonymous response shapes for further adapter qualification. No API calls, credentials, server or external assets are needed. Both the input and HTML report contain confidential configuration evidence; keep them outside the repository and do not publish or upload them.

### Local configuration workspace

Run `python central_tool.py app --directory <private-audit-directory>` to open a loopback-only browser application. It lists saved configuration audit snapshots, opens the existing explorer, and compares two devices of the same persona within one snapshot. Device comparisons exclude infrastructure by default; explicitly select a module to include it. Exact differences do not prove behavioral equivalence.

Use a separate directory per customer. The application does not independently verify tenant identity. Enter client ID, client secret and region directly in the browser and select Connect and refresh. Credentials and access tokens are held in process memory only for the audit and are not deliberately persisted, logged, or returned to the browser. The application cannot control browser password managers, OS paging or crash dumps; decline save prompts. For legacy automation, environment credentials with `--enable-refresh --region-file <region-file>` remain supported. Module coverage lists fully qualified modules first, distinguishes partial from unqualified scopes, and links to evidence. No scope is authorized for writes. Refresh creates a new private audit file; only one refresh can run at a time. The server binds to 127.0.0.1 on a random port, uses a random session URL, validates Host, refresh Origin/fetch metadata and a separate anti-CSRF form token, disables caching and framing, and does not log request URLs. Keep the local session URL private. Press Ctrl+C to stop. No dependencies or database are required.

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

Scoped reads, Library collections and additional profile types use at most four concurrent read workers. OAuth token renewal is serialized; HTTP 429 retries share a cooldown across workers. Scope review occurs after capture so the Global baseline is available independently of request completion order. No modules or applicable scopes are skipped for speed. Actual latency and throughput depend on Central and its rate limits; validate against a live capture.

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
