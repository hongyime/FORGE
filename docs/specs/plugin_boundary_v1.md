# Plugin Boundary Specification v1

**Status:** Draft
**Version:** 1.0
**Scope:** FORGE plugin event boundary (collaboration only)
**Non-Scope:** C2 features (agents, beacons, implants, command execution)

---

## 1. Purpose

FORGE is a **collaboration and artifact management toolkit**. It is explicitly
**NOT a C2 (Command and Control) framework**. This document defines the strict
boundary between FORGE core and third-party plugins, ensuring that plugins can
extend collaboration workflows **without** enabling agent-style capabilities.

Any C2-adjacent capability (agent registration, beacon check-in, command
dispatch, payload delivery) is out of scope and MUST NOT be introduced through
the plugin boundary.

---

## 2. Scope Definition

### 2.1 What Events MAY Cross the Plugin Boundary

Only the following event categories are permitted:

| Event Type              | Purpose                                                |
|-------------------------|--------------------------------------------------------|
| `artifact:discovered`   | New artifact registered (metadata only)                |
| `graph:updated`         | Knowledge-graph node/edge change (references only)     |
| `report:generated`      | Report produced (metadata + path only)                 |
| `collection:progress`   | Progress/status update for a collection or scan        |

Any event type not in this list MUST be rejected by the event bus.

### 2.2 What Data MAY Be Exchanged

- **Artifact metadata:** `id`, `type`, `source`, `timestamp`
- **Graph node references:** `id`, `type` — **NO node properties**, **NO edge payloads**
- **Report metadata:** `type`, `engagement_id`, `path`
- **Status messages:** `progress` (0–100), `state`, human-readable `message`

Data MUST be limited to identifiers and shallow metadata. Content bodies,
attachments, and property blobs stay on the FORGE side of the boundary.

### 2.3 What is FORBIDDEN

The following MUST NEVER cross the plugin boundary:

- ❌ Credentials, passwords, secrets
- ❌ API keys, tokens, session data
- ❌ Execution commands or payloads
- ❌ Binary data or executables
- ❌ Database queries or direct DB access
- ❌ Agent lifecycle commands (register, heartbeat, check-in)
- ❌ Remote-shell, RPC, or arbitrary code-execution primitives
- ❌ Raw file contents (only paths + metadata permitted)

---

## 3. Event Schema (JSON Schema Draft 2020-12)

All plugin events MUST validate against the following schema **before**
reaching any handler. Validation failure results in the event being dropped
and an audit-log entry.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://forgetoolkit.local/schemas/plugin-event-v1.json",
  "title": "FORGE Plugin Event v1",
  "type": "object",
  "required": ["event_type", "timestamp", "engagement_id", "plugin_id", "payload"],
  "additionalProperties": false,
  "properties": {
    "event_type": {
      "type": "string",
      "enum": [
        "artifact:discovered",
        "graph:updated",
        "report:generated",
        "collection:progress"
      ]
    },
    "timestamp": {
      "type": "string",
      "format": "date-time"
    },
    "engagement_id": {
      "type": "integer",
      "minimum": 1
    },
    "plugin_id": {
      "type": "string",
      "pattern": "^[a-z0-9_-]+$",
      "minLength": 3,
      "maxLength": 64
    },
    "payload": {
      "type": "object",
      "maxProperties": 50
    }
  }
}
```

### 3.1 Per-Event Payload Contracts

#### `artifact:discovered`

```json
{
  "artifact_id": "integer (>=1)",
  "artifact_type": "string",
  "source": "string",
  "discovered_at": "string (date-time)"
}
```

#### `graph:updated`

```json
{
  "node_id": "string",
  "node_type": "string",
  "operation": "one of: created | updated | removed"
}
```

Node **properties** and edge **payloads** MUST NOT be included.

#### `report:generated`

```json
{
  "report_type": "string",
  "engagement_id": "integer (>=1)",
  "path": "string (relative path within engagement workspace)"
}
```

#### `collection:progress`

```json
{
  "collection_id": "string",
  "progress": "integer (0..100)",
  "state": "one of: pending | running | completed | failed",
  "message": "string (<=280 chars, human-readable)"
}
```

---

## 4. Data Exchange Contract

| Rule                       | Specification                                                                 |
|----------------------------|-------------------------------------------------------------------------------|
| Allowed JSON types         | `string`, `integer`, `boolean`, `array`, `object`                             |
| Disallowed types           | `null` in required fields, binary blobs, base64-encoded executables           |
| Maximum payload size       | **10 KB** JSON-encoded (UTF-8, post-serialization)                            |
| Maximum nesting depth      | 5 levels                                                                      |
| Maximum `payload` keys     | 50 (enforced by schema `maxProperties`)                                       |
| Forbidden field patterns   | `password`, `secret`, `token`, `api_key`, `credential`, `private`, `passwd`, `auth` — case-insensitive, substring match on any key at any depth |
| Validation                 | Strict schema enforcement + forbidden-key scan **before** dispatch            |
| Encoding                   | UTF-8 JSON only; no MessagePack, CBOR, protobuf, or binary framing at this boundary |

Any event that violates ANY rule above MUST be dropped and audit-logged. It
MUST NOT reach any subscriber.

---

## 5. Security Considerations

### 5.1 Isolation

- **No direct DB access:** Plugins interact only via the event bus. No plugin
  code executes SQL, ORM queries, or filesystem I/O against FORGE storage.
- **Engagement scoping:** Every event carries `engagement_id`. A plugin
  registered against engagement `E` MUST NOT emit events for any other
  engagement. The bus enforces this binding at dispatch time.
- **Process isolation (recommended):** Plugins SHOULD run out-of-process
  (subprocess, container, or sidecar) with an IPC boundary. In-process
  plugins are permitted for trusted, first-party extensions only.

### 5.2 Authentication & Binding

- Every plugin is issued a `plugin_id` at registration.
- The bus enforces `(plugin_id, engagement_id)` binding on every event.
- Plugin identity MUST be verified before its first event is accepted.

### 5.3 Rate Limiting

- **100 events / minute / plugin** hard cap.
- Burst allowance: 20 events / 10 seconds.
- Over-limit events are dropped and audit-logged; repeated offenders are
  auto-disabled for the engagement.

### 5.4 Audit Logging

Every event dispatched or rejected MUST be logged with:

- Timestamp (ISO 8601, UTC)
- `plugin_id`, `engagement_id`, `event_type`
- Outcome: `accepted` | `rejected:<reason>` | `rate_limited`
- Payload size (bytes)

Audit logs stay on the FORGE side and are NOT exposed through the plugin
boundary.

### 5.5 Threat Model (summary)

| Threat                              | Mitigation                                    |
|-------------------------------------|-----------------------------------------------|
| Credential exfiltration via events  | Forbidden field-name scan + schema whitelist  |
| Cross-engagement data leakage       | `(plugin_id, engagement_id)` binding at bus   |
| Denial of service via event flood   | Rate limiting + auto-disable                  |
| Payload smuggling (binaries)        | JSON-only, 10 KB cap, type whitelist          |
| Schema drift / new event types      | Strict enum enforcement on `event_type`       |
| Plugin impersonation                | Plugin identity check on registration         |

---

## 6. Non-Goals (Explicitly Out of Scope)

The plugin boundary **DOES NOT** and **WILL NOT** support:

1. **Agent lifecycle management** — no registration, heartbeat, check-in,
   or cleanup events for remote agents.
2. **Beacon / implant communication** — no jitter, sleep, kill-date, or
   any beacon-style scheduling primitives.
3. **Command execution or payload delivery** — no shell commands, no
   binary uploads, no in-band task queues.
4. **Real-time remote control** — no interactive sessions, no PTY
   forwarding, no reverse tunnels.
5. **File transfer protocols** — no chunked upload/download, no
   base64-encoded file bodies. Only file *paths* and *metadata* cross the
   boundary; the file bytes stay on FORGE storage.
6. **Arbitrary RPC** — plugins do not invoke FORGE internals; the bus is
   one-way (plugin → FORGE) plus a strictly-typed notification channel
   back (FORGE → plugin) using the same schema.

Any request to add such capabilities is a **specification change** and MUST
go through a new versioned boundary spec, NOT a plugin PR.

---

## 7. Reference: Existing Event Bus

Implementations of this boundary integrate with FORGE's existing internal
event bus. This spec is **implementation-agnostic** — it defines the contract,
not the transport. Suitable transports include:

- In-process pub/sub (for trusted first-party plugins)
- Unix domain socket / named pipe (out-of-process, single-host)
- Local HTTP + bearer token (out-of-process, containerized)

The schema and security rules in §3–§5 apply uniformly to every transport.

---

## 8. Versioning

- This document is `plugin_boundary_v1`.
- Backward-incompatible changes require `plugin_boundary_v2` with a
  migration note. `v1` remains valid until formally deprecated.
- Additive changes (new event types, new optional payload fields) MUST NOT
  remove or reinterpret existing fields.

---

## 9. Conformance Checklist

An implementation conforms to this spec iff:

- [ ] Only the four event types in §2.1 are accepted.
- [ ] JSON Schema (§3) validation runs before every dispatch.
- [ ] Forbidden field-name scan (§4) runs before every dispatch.
- [ ] 10 KB / 50-key / depth-5 caps enforced.
- [ ] `(plugin_id, engagement_id)` binding enforced at bus.
- [ ] 100 events/minute rate limit enforced per plugin.
- [ ] All dispatch attempts (accepted + rejected) audit-logged.
- [ ] No agent-lifecycle, beacon, command, or file-transfer event types
      exist anywhere in the plugin surface.
