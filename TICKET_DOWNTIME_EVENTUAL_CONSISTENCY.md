# Origin/Cache Downtime Table Should Not Rely on Registry Responses

## Summary

The Origin/Cache should not rely on a response from the Registry to populate its own downtime table. We should trade "immediately consistent" for "eventually consistent" when it comes to potential skew between what the Origin/Cache knows about its downtime and what the Registry/Director knows about the downtime.

## Current Behavior

Currently, the Director periodically fetches federation-level downtimes from the Registry via the `/api/v1.0/downtime` endpoint (see `director/cache_ads.go:533-626`). Origin/Cache servers maintain their own local downtime tables and advertise them to the Director.

## Proposed Change

Origin/Cache servers should independently manage their downtime tables without requiring synchronous responses from the Registry. This approach accepts eventual consistency, where:

- Origin/Cache maintain authoritative local downtime state
- Registry/Director may have temporarily inconsistent views of downtime status
- Consistency is achieved eventually through periodic advertisement/synchronization

## Benefits

- Reduces coupling between Origin/Cache and Registry
- Improves resilience (Origin/Cache can manage downtimes even if Registry is unavailable)
- Simplifies downtime management at the server level

## Affected Components

- `cache/advertise.go` (lines 57-61)
- `origin/advertise.go` (lines 164-168)
- `director/cache_ads.go` (downtime handling logic)
- `database/server.go` (downtime queries)
