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
