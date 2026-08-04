# cloud_ref seed type — implementation plan

**Status:** scoped, not implemented (deferred to a dedicated session)  
**Author:** Kiro (yolo agent), 2026-08-04  
**Trigger:** `docs/engagement_overhaul_tasklist.md` §Compact active backlog —
"Next checkpoint: add first-class `cloud_ref` seed support if still
product-required."

---

## What's the gap today

The `engagement_seeds` table constrains `seed_type` to twelve values:

```sql
seed_type TEXT NOT NULL CHECK (seed_type IN (
    'domain','email','phone','username','ipv4','ipv6',
    'name','company','url','apk_url','subdomain','other'
))
```

Live cloud provider references (Supabase `xyz.supabase.co`, Firebase
`myapp.firebaseio.com`, Amplify `d123abc.cloudfront.net`, Vercel deployments,
Netlify sites, GCS buckets, S3 buckets, Azure Storage accounts) currently
land as one of:

- `url` — when the ref surfaces as a full `https://...` URL from Playwright /
  Common Crawl / Wayback / config extraction
- `other` — when only a bare provider ID / hostname was recovered

`forge/utils/intel/provider_urls.py:provider_url_seed_type()` already knows how
to spot cloud provider hostnames but has no dedicated bucket to promote them
to. That means:

1. **Reporting can't group them.** The Phase 6 template and dashboard filter
   on `seed_type IN ('domain', 'subdomain')` etc.; cloud refs get scattered.
2. **Attack-graph node typing is wrong.** `phase4/attack_path.py:_seed_node_type`
   coerces cloud refs into `NodeType.HOST` or `NodeType.APP` depending on
   URL shape — not a semantic cloud identity.
3. **Scope-manifest routing is manual.** `cli.py:_scope_manifest_seed_targets`
   and `phase4/cloud_validate.py:_validation_scope_seed_targets` special-case
   provider hostnames in `str.contains` heuristics rather than reading the
   authoritative `seed_type`.
4. **Recursive discovery keeps re-classifying.** Every pivot round the
   classifier reruns because there's no persistent typed label.

---

## Definition of done

A `cloud_ref` seed:

- Persists as `seed_type='cloud_ref'` end-to-end (DB → API → dashboard →
  report → graph → export).
- Round-trips through the whole pipeline without ever silently becoming
  `url` or `other`.
- Stays scope-gated: `assert_in_scope` still evaluates cloud refs against
  domains / IP ranges / URL prefixes, and validation-before-reporting
  (V-11+) still applies.
- Never bypasses `--dry-run` or `FORGE_REQUIRE_SCOPE_MANIFEST`.
- Has a canonical short label (e.g. `supabase://xyz`, `firebase://myapp`,
  `s3://bucket-name`) for display, distinct from the underlying URL.

---

## File-level change map

Total blast radius: ~14 files, ~350 lines. All changes are additive on the
happy path (add `cloud_ref` to the enum, wire consumers).

### 1. Schema + migration (blocks everything else)

- `forge/db/schema.py:53-58` — extend the CHECK list.
- `forge/db/migrations.py:718-724` — extend the CHECK list on `engagement_seeds`
  and any mirrored constraint on `discovered_seeds` (line 766).
- **New migration** (Alembic + raw SQLite path): SQLite can't `ALTER TABLE`
  a CHECK constraint. Standard rewrite:
  ```sql
  CREATE TABLE engagement_seeds_new ( ... CHECK ... including 'cloud_ref' ... );
  INSERT INTO engagement_seeds_new SELECT * FROM engagement_seeds;
  DROP TABLE engagement_seeds;
  ALTER TABLE engagement_seeds_new RENAME TO engagement_seeds;
  -- re-create indexes, triggers, foreign keys
  ```
  Test with `tests/db/test_migrations.py` (add a fixture engagement with
  legacy `url`-typed cloud refs and confirm the rewrite preserves them).

### 2. Classifier

- `forge/engagement_orchestrator.py:333 _classify_seed_value()` — insert a
  cloud-ref check **before** the URL fallback. Reuse
  `provider_urls.provider_url_seed_type()` — it already spots
  `supabase.co`, `firebaseio.com`, `s3.amazonaws.com`, etc.
- `forge/webui/app.py:425 _classify_seed_value()` — duplicate classifier;
  keep in sync (there's a shared-helper TODO here too).
- `forge/utils/intel/provider_urls.py:108 provider_url_seed_type()` — return
  `'cloud_ref'` for provider URLs instead of `'url'`, keeping the URL as
  the persisted `seed_value` and the canonical `cloud_ref://provider/ident`
  as a new `metadata_json.canonical_ref` field.

### 3. Canonicalization

- `forge/webui/app.py:479 _canonical_seed_value()` — new branch: when
  `seed_type == 'cloud_ref'` and value contains a provider URL, extract
  the provider + project ID / bucket and produce `provider://ident`.
- Every persistence site should use the canonical form so
  `UNIQUE (engagement_id, seed_type, seed_value)` deduplicates across
  discovery rounds.

### 4. Scope-manifest routing

- `forge/cli.py:425 _scope_manifest_seed_targets()` — accept `cloud_ref`,
  return the underlying host + URL prefix pair for scope matching.
- `forge/phase4/cloud_validate.py:4222 _validation_scope_seed_targets()` —
  same, plus route to the correct cloud validator by provider prefix.

### 5. Consumers (report / dashboard / graph)

- `forge/phase4/attack_path.py:687 _seed_node_type()` — add `cloud_ref` →
  `NodeType.CLOUD_ASSET` (may need a new NodeType if none exists; check
  `forge/models/attack_graph_models.py:33 NodeType` enum).
- `forge/phase6/report_synthesizer.py:452 _safe_seed_display_value()` —
  format cloud refs as `[cloud] supabase://xyz` for prose safety.
- `forge/phase6/report_synthesizer.py:1004` and downstream — extend the
  `seed_type IN (...)` filters that gate report inclusion.
- `forge/reporting/dashboard.py:405, 447` — add `cloud_ref` to the domain /
  subdomain / email groupings so cloud refs get their own section instead
  of falling into "other".
- `forge/reporting/dashboard.py:1888 _seed_graph_node_type()` — mirror the
  attack-path change.

### 6. API + JSON serialization

- Grep for `seed_type in {` and `seed_type == "url"` — every place a
  cloud ref could hide as `url` needs a companion `cloud_ref` branch.

---

## Testing plan

Minimum bar to merge:

| Test | Purpose |
|---|---|
| `tests/db/test_cloud_ref_migration.py` | Legacy `url`-typed cloud refs migrate correctly; unique constraint holds. |
| `tests/orchestrator/test_seed_classifier_cloud_ref.py` | Classifier emits `cloud_ref` for Supabase/Firebase/GCS/S3/Azure/Amplify/Vercel/Netlify hostnames. |
| `tests/orchestrator/test_seed_dedup_across_types.py` | `xyz.supabase.co` and `https://xyz.supabase.co/rest/v1` collapse to one canonical `cloud_ref` row. |
| `tests/opsec/test_cloud_ref_scope_gate.py` | Cloud refs remain scope-gated; out-of-scope refs raise `ScopeViolationError` even when the URL looks like a legitimate provider hostname. |
| `tests/phase6/test_report_cloud_ref_grouping.py` | Report Markdown, JSON, CSV, dashboard, and MTGX export all group cloud refs distinctly. |
| `tests/phase4/test_attack_graph_cloud_node.py` | Attack graph shows cloud refs as their own node type. |
| `tests/integration/test_kill_chain_cloud_ref_e2e.py` | Full multi-seed kill-chain run persists cloud refs, routes them to `cloud validate`, and includes them in the final report + audit manifest. |

Non-negotiable safety guards to include in each test:

- ROE / scope-manifest requirement holds — a non-dry-run flow without ROE
  raises before any cloud ref is enqueued.
- Validation-before-reporting still applies — an unvalidated cloud ref
  never lands in the report as `VULN`; it stays `INFO` or is suppressed.
- `--dry-run` never issues any outbound HTTP.

---

## Estimated effort

Approximate, based on the file-level diff:

| Slice | Effort |
|---|---|
| Schema + migration + rollback fixture | 2 h |
| Classifier + canonicalizer + provider-url helper | 1.5 h |
| Consumer sweep (report / dashboard / graph / scope) | 2.5 h |
| Test coverage (unit + integration) | 2 h |
| Full-suite regression + docstring sync | 1 h |
| **Total** | **~9 h (one focused day)** |

---

## What is NOT in scope

- **New provider families.** This work only formalises the seed type;
  which provider families FORGE recognises is unchanged.
- **Live cloud enumeration.** cloud_ref remains a static observation.
  Actual scoped live probes still live behind `--attack-mode` +
  `--roe-id` + `--scope-manifest`.
- **Backwards deletion.** Existing legacy `url`-typed cloud refs on
  historical engagements should be **rewritten in place** by the
  migration, not deleted. Preserve audit lineage.

---

## Recommended session shape when picking this up

1. Fresh session dedicated to this checkpoint. cloud_ref touches
   validation, reporting, and dashboard — the whole read side of the
   pipeline. Bundling with unrelated fixes will make review harder.
2. Start with schema + migration + one classifier test. Push. Verify
   nothing regresses.
3. Then classifier + canonicalizer + provider-urls in one commit.
   Push. Verify.
4. Then each consumer as its own commit. Push after each.
5. Finally integration test + full-suite regression. Push. Update
   `docs/claude_quick_handoff.md` and mark the tasklist checkbox.
