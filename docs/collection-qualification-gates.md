# Qualification gates for collection optimization

## Supplemental applicability

Vendor feature documentation is not an exclusion contract for committed or effective GET responses. AP-only feature descriptions for IDS, time ranges and AirGroup are recorded in the anonymous applicability report; actual device inventory is distinguished from the requested device-function filter. A positive response on an otherwise unsupported platform remains captured. No Deep scope is removed by this analysis. Only an explicit API-level exclusion contract, validated against complete selector-level evidence, can justify pruning.

## Incremental collection

The documented Audit Trail WebSocket endpoint is a potential future change signal:
- https://developer.arubanetworks.com/new-central/docs/streaming-api-event-audit-trail
- https://developer.arubanetworks.com/new-central/docs/streaming-api-getting-started
- https://developer.arubanetworks.com/new-central/docs/streaming-api-connection-management
- https://developer.arubanetworks.com/new-central/docs/streaming-modes

The stream schema includes scope IDs, changed fields and impact radius, but their live availability and coverage are unqualified. Streaming requires Advanced-tier subscriptions. Mirror mode requires a unique subscriber ID; sharing the default ID can distribute events across connections rather than give every connection every event. The vendor documents a 15-minute reconnect queue for unexpected disconnects; after expiry events are lost.

Before reusing prior configuration, require authoritative event coverage for changes to definitions, assignments, membership, inventory, inherited effective configuration, NAC and other captured resources; live scope/module/identity mapping; dependency invalidation; reconciled replay and gap detection; a qualified initial snapshot and continuous tenant continuity; and evidence from actual changes and deliberately disconnected/reconnected clients. Unknown event, missing fields, expired queue, unavailable subscription, tenant mismatch or incomplete evidence must force a full refresh, never silently reuse stale configuration. Do not assume a quiet stream means no change. Historical REST audit reconciliation alone does not qualify these guarantees.

No persistent listener, dependencies, credentials or incremental collection policy are introduced. The existing fresh Deep capture and explicit checkpoint semantics are unchanged.
