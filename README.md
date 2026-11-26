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
