import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { formatRelativeTime, pageWindow } from './artifact-status-utils'

/**
 * ArtifactStatusTab
 *
 * Displays the artifact enrichment queue for an engagement. Fetches from
 * `/api/engagements/{engagementId}/artifact-queue` (U3.1). Supports
 * state filtering, pagination, click-to-expand error rows, keyboard
 * navigation, and user-visible auto-refresh (30s) with "last updated"
 * indicator.
 *
 * Contract (U3.1):
 *   GET /api/engagements/{id}/artifact-queue?state=...&page=...&page_size=...
 *   -> {
 *        items: ArtifactQueueRow[],
 *        page: number,          // 1-based
 *        page_size: number,
 *        total: number,         // total rows matching filter
 *        total_pages: number,
 *        generated_at: string,  // ISO
 *      }
 */

export type ArtifactState =
  | 'pending'
  | 'processing'
  | 'complete'
  | 'failed'

export type ArtifactQueueRow = {
  id: number | string
  artifact_name: string
  parser: string
  state: ArtifactState | string
  timestamp: string // ISO 8601
  error_msg?: string | null
}

export type ArtifactQueueResponse = {
  items: ArtifactQueueRow[]
  page: number
  page_size: number
  total: number
  total_pages: number
  generated_at?: string
}

export type ArtifactQueueFilter = 'all' | ArtifactState

export type ArtifactStatusTabProps = {
  engagementId: string | number
  /** Bearer token for authenticated live-mode fetches. Null/undefined => unauthenticated. */
  token?: string | null
  /** Auto-refresh interval in ms. Default 30_000. Set 0 to disable. */
  refreshIntervalMs?: number
  /** Rows per page. Default 25. */
  pageSize?: number
  /** Injectable fetch for tests. Defaults to `window.fetch`. */
  fetcher?: typeof fetch
  /** Time provider for tests. Defaults to `() => new Date()`. */
  now?: () => Date
}

const DEFAULT_REFRESH_MS = 30_000
const DEFAULT_PAGE_SIZE = 25

const STATE_ORDER: ArtifactQueueFilter[] = [
  'all',
  'pending',
  'processing',
  'complete',
  'failed',
]

const STATE_LABEL: Record<ArtifactQueueFilter, string> = {
  all: 'All states',
  pending: 'Pending',
  processing: 'Processing',
  complete: 'Complete',
  failed: 'Failed',
}

function classifyState(state: string): ArtifactState | 'unknown' {
  switch (state) {
    case 'pending':
    case 'processing':
    case 'complete':
    case 'failed':
      return state
    default:
      return 'unknown'
  }
}

function buildQueryString(state: ArtifactQueueFilter, page: number, pageSize: number): string {
  const params = new URLSearchParams()
  if (state !== 'all') params.set('state', state)
  params.set('page', String(page))
  params.set('page_size', String(pageSize))
  return params.toString()
}

function apiHeaders(token: string | null | undefined): HeadersInit {
  return token ? { Authorization: `Bearer ${token}` } : {}
}

type LoadStatus = 'idle' | 'loading' | 'ok' | 'error'

export function ArtifactStatusTab(props: ArtifactStatusTabProps) {
  const {
    engagementId,
    token,
    refreshIntervalMs = DEFAULT_REFRESH_MS,
    pageSize = DEFAULT_PAGE_SIZE,
    fetcher,
    now = () => new Date(),
  } = props

  const [stateFilter, setStateFilter] = useState<ArtifactQueueFilter>('all')
  const [page, setPage] = useState(1)
  const [data, setData] = useState<ArtifactQueueResponse | null>(null)
  const [status, setStatus] = useState<LoadStatus>('idle')
  const [errorMessage, setErrorMessage] = useState<string>('')
  const [lastLoadedAt, setLastLoadedAt] = useState<Date | null>(null)
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set())
  const [tick, setTick] = useState(0) // forces "last updated" label refresh

  const abortRef = useRef<AbortController | null>(null)

  const doFetch = fetcher ?? (typeof window !== 'undefined' ? window.fetch.bind(window) : undefined)

  const load = useCallback(async () => {
    if (!doFetch) {
      setStatus('error')
      setErrorMessage('fetch is unavailable in this environment')
      return
    }
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller
    setStatus('loading')
    setErrorMessage('')

    const qs = buildQueryString(stateFilter, page, pageSize)
    const url = `/api/engagements/${encodeURIComponent(String(engagementId))}/artifact-queue?${qs}`

    try {
      const response = await doFetch(url, {
        headers: apiHeaders(token),
        signal: controller.signal,
      })
      if (!response.ok) {
        throw new Error(`artifact-queue fetch failed: ${response.status}`)
      }
      const payload = (await response.json()) as ArtifactQueueResponse
      setData(payload)
      setStatus('ok')
      setLastLoadedAt(now())
    } catch (error) {
      if ((error as { name?: string }).name === 'AbortError') return
      setStatus('error')
      setErrorMessage(
        error instanceof Error ? error.message : 'artifact-queue fetch failed',
      )
    }
  }, [doFetch, engagementId, now, page, pageSize, stateFilter, token])

  // Initial + dependency-driven load.
  useEffect(() => {
    void load()
    return () => {
      abortRef.current?.abort()
    }
  }, [load])

  // Auto-refresh (user-visible; "last updated" chip below the toolbar).
  useEffect(() => {
    if (!refreshIntervalMs || refreshIntervalMs <= 0) return
    const handle = window.setInterval(() => {
      void load()
    }, refreshIntervalMs)
    return () => window.clearInterval(handle)
  }, [load, refreshIntervalMs])

  // Re-render every 15s so the relative "last updated" text stays honest
  // without hitting the network.
  useEffect(() => {
    const handle = window.setInterval(() => setTick((n) => n + 1), 15_000)
    return () => window.clearInterval(handle)
  }, [])

  const rows = data?.items ?? []
  const totalPages = data?.total_pages ?? 1
  const currentPage = data?.page ?? page
  const total = data?.total ?? rows.length

  const pageNumbers = useMemo(() => pageWindow(currentPage, totalPages), [currentPage, totalPages])

  const goToPage = useCallback(
    (target: number) => {
      const clamped = Math.max(1, Math.min(totalPages, target))
      if (clamped !== page) setPage(clamped)
    },
    [page, totalPages],
  )

  const onFilterChange = useCallback((value: ArtifactQueueFilter) => {
    setStateFilter(value)
    setPage(1)
  }, [])

  const toggleExpand = useCallback((id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const lastUpdatedLabel = lastLoadedAt
    ? `Last updated ${formatRelativeTime(lastLoadedAt.toISOString(), now())}`
    : status === 'loading'
      ? 'Loading…'
      : 'Not loaded yet'

  // `tick` is intentionally referenced so eslint knows the label depends on it.
  void tick

  return (
    <section
      className="panel artifact-status-tab"
      aria-label="Artifact enrichment queue"
    >
      <header className="artifact-status-toolbar">
        <div className="artifact-status-filter">
          <label htmlFor="artifact-status-filter-select">Filter by state</label>
          <select
            id="artifact-status-filter-select"
            value={stateFilter}
            onChange={(event) => onFilterChange(event.target.value as ArtifactQueueFilter)}
            aria-label="Filter artifacts by state"
          >
            {STATE_ORDER.map((value) => (
              <option key={value} value={value}>
                {STATE_LABEL[value]}
              </option>
            ))}
          </select>
        </div>

        <div className="artifact-status-meta" aria-live="polite">
          <span data-testid="artifact-last-updated">{lastUpdatedLabel}</span>
          {refreshIntervalMs > 0 && (
            <span className="muted-copy">
              {' '}· auto-refresh every {Math.round(refreshIntervalMs / 1000)}s
            </span>
          )}
          <button
            type="button"
            onClick={() => void load()}
            disabled={status === 'loading'}
            aria-label="Refresh artifact queue now"
          >
            {status === 'loading' ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
      </header>

      {status === 'error' && (
        <div
          role="alert"
          className="artifact-status-error"
          data-testid="artifact-error-banner"
        >
          <p>Failed to load artifact queue: {errorMessage}</p>
          <button type="button" onClick={() => void load()}>
            Retry
          </button>
        </div>
      )}

      <div className="artifact-status-table-wrap" role="region" aria-label="Artifact queue table" tabIndex={0}>
        <table className="artifact-status-table">
          <caption className="visually-hidden">
            Artifact enrichment queue — {total} row{total === 1 ? '' : 's'}
            {stateFilter !== 'all' ? `, filtered to ${STATE_LABEL[stateFilter]}` : ''}
          </caption>
          <thead>
            <tr>
              <th scope="col">Artifact</th>
              <th scope="col">Parser</th>
              <th scope="col">State</th>
              <th scope="col">Timestamp</th>
              <th scope="col">Error</th>
            </tr>
          </thead>
          <tbody>
            {status === 'loading' && rows.length === 0
              ? renderSkeletonRows(pageSize)
              : rows.length === 0
                ? (
                    <tr>
                      <td colSpan={5} className="artifact-status-empty">
                        {status === 'error'
                          ? 'No data (see error above).'
                          : stateFilter === 'all'
                            ? 'No artifacts queued yet.'
                            : `No artifacts in state “${STATE_LABEL[stateFilter]}”.`}
                      </td>
                    </tr>
                  )
                : rows.map((row) => (
                    <ArtifactRow
                      key={String(row.id)}
                      row={row}
                      expanded={expandedIds.has(String(row.id))}
                      onToggle={() => toggleExpand(String(row.id))}
                      now={now()}
                    />
                  ))}
          </tbody>
        </table>
      </div>

      <nav className="artifact-status-pagination" aria-label="Artifact queue pagination">
        <button
          type="button"
          onClick={() => goToPage(currentPage - 1)}
          disabled={currentPage <= 1 || status === 'loading'}
          aria-label="Previous page"
        >
          ‹ Prev
        </button>
        <ul className="artifact-status-pages" role="list">
          {pageNumbers.map((entry) =>
            entry === 'gap' ? (
              <li key={`gap-${Math.random()}`} aria-hidden="true" className="artifact-status-page-gap">
                …
              </li>
            ) : (
              <li key={entry}>
                <button
                  type="button"
                  aria-current={entry === currentPage ? 'page' : undefined}
                  aria-label={`Go to page ${entry}`}
                  onClick={() => goToPage(entry)}
                  disabled={status === 'loading' && entry !== currentPage}
                >
                  {entry}
                </button>
              </li>
            ),
          )}
        </ul>
        <button
          type="button"
          onClick={() => goToPage(currentPage + 1)}
          disabled={currentPage >= totalPages || status === 'loading'}
          aria-label="Next page"
        >
          Next ›
        </button>
        <span className="muted-copy" aria-live="polite">
          Page {currentPage} of {totalPages} · {total} row{total === 1 ? '' : 's'}
        </span>
      </nav>
    </section>
  )
}

type ArtifactRowProps = {
  row: ArtifactQueueRow
  expanded: boolean
  onToggle: () => void
  now: Date
}

function ArtifactRow({ row, expanded, onToggle, now }: ArtifactRowProps) {
  const kind = classifyState(row.state)
  const hasError = Boolean(row.error_msg && row.error_msg.trim().length > 0)
  const canExpand = hasError
  const rowId = `artifact-row-${row.id}`
  const errorPanelId = `artifact-row-${row.id}-error`

  return (
    <>
      <tr
        id={rowId}
        data-testid={`artifact-row-${row.id}`}
        data-state={kind}
        className={`artifact-status-row artifact-status-row-${kind}`}
      >
        <th scope="row" className="artifact-status-cell-name" title={row.artifact_name}>
          {row.artifact_name}
        </th>
        <td>{row.parser || '—'}</td>
        <td>
          <span className={`artifact-status-badge artifact-status-badge-${kind}`}>
            {kind === 'unknown' ? row.state : STATE_LABEL[kind]}
          </span>
        </td>
        <td>
          <time dateTime={row.timestamp} title={row.timestamp}>
            {formatRelativeTime(row.timestamp, now)}
          </time>
        </td>
        <td>
          {canExpand ? (
            <button
              type="button"
              onClick={onToggle}
              aria-expanded={expanded}
              aria-controls={errorPanelId}
              data-testid={`artifact-row-${row.id}-toggle`}
            >
              {expanded ? 'Hide error' : 'Show error'}
            </button>
          ) : (
            <span className="muted-copy">—</span>
          )}
        </td>
      </tr>
      {canExpand && expanded && (
        <tr
          id={errorPanelId}
          data-testid={`artifact-row-${row.id}-error-panel`}
          className="artifact-status-error-row"
        >
          <td colSpan={5}>
            <pre className="artifact-status-error-detail">{row.error_msg}</pre>
          </td>
        </tr>
      )}
    </>
  )
}

function renderSkeletonRows(count: number) {
  const n = Math.min(Math.max(count, 3), 10)
  return Array.from({ length: n }).map((_, index) => (
    <tr key={`skeleton-${index}`} data-testid="artifact-skeleton-row" aria-hidden="true">
      <td colSpan={5} className="artifact-status-skeleton-cell">
        <span className="artifact-status-skeleton-bar" />
      </td>
    </tr>
  ))
}

export default ArtifactStatusTab
