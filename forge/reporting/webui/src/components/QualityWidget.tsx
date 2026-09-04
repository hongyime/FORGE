import './QualityWidget.css'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { classifyScore } from './quality-widget-utils'

/**
 * QualityWidget - displays engagement data-quality health.
 *
 * NOTE ON PATH: task specified `forge/webui/components/QualityWidget.tsx`,
 * but `forge/webui/` is the Python/FastAPI/HTMX backend. The real React
 * dashboard lives at `forge/reporting/webui/src/`. Placed here so it compiles
 * and integrates with the existing App shell.
 *
 * Contract: fetches `/api/engagements/{engagementId}/quality`, listens for
 * WebSocket `quality:updated` events to refresh without a full re-mount, and
 * renders four metrics + score + inline SVG sparkline of the last 5 runs.
 */

export type QualityMetricKey = 'coverage' | 'completeness' | 'freshness' | 'connectivity'

export type QualityMetric = {
  key: QualityMetricKey
  label: string
  score: number // 0..100
}

export type QualityRunPoint = {
  timestamp: string
  score: number // 0..100
}

export type QualitySnapshot = {
  engagement_id: string
  overall_score: number // 0..100
  generated_at: string
  metrics: QualityMetric[]
  history: QualityRunPoint[] // most recent last; component takes last 5
}

export type QualityThreshold = 'good' | 'warn' | 'bad'

function thresholdIcon(state: QualityThreshold): string {
  if (state === 'good') {
    return '🟢'
  }
  if (state === 'warn') {
    return '🟡'
  }
  return '🔴'
}

function thresholdColor(state: QualityThreshold): string {
  if (state === 'good') {
    return '#4ade80'
  }
  if (state === 'warn') {
    return '#facc15'
  }
  return '#f87171'
}

const METRIC_ORDER: QualityMetricKey[] = ['coverage', 'completeness', 'freshness', 'connectivity']

const METRIC_LABELS: Record<QualityMetricKey, string> = {
  coverage: 'Coverage',
  completeness: 'Completeness',
  freshness: 'Freshness',
  connectivity: 'Connectivity',
}

function normalizeMetrics(metrics: QualityMetric[]): QualityMetric[] {
  const byKey = new Map(metrics.map((metric) => [metric.key, metric]))
  return METRIC_ORDER.map((key) => {
    const found = byKey.get(key)
    return {
      key,
      label: found?.label ?? METRIC_LABELS[key],
      score: found?.score ?? 0,
    }
  })
}

function lastFive(points: QualityRunPoint[]): QualityRunPoint[] {
  if (points.length <= 5) {
    return points
  }
  return points.slice(points.length - 5)
}

export type SparklineProps = {
  points: QualityRunPoint[]
  width?: number
  height?: number
  strokeColor?: string
}

/**
 * Sparkline - inline SVG line chart. No external chart library.
 * Renders even for 1 point (as a dot). Testable via data-testid="quality-sparkline"
 * and data-testid="quality-sparkline-point".
 */
export function Sparkline({
  points,
  width = 160,
  height = 40,
  strokeColor = '#55c4cc',
}: SparklineProps) {
  const trimmed = useMemo(() => lastFive(points), [points])

  if (trimmed.length === 0) {
    return (
      <svg
        className="quality-sparkline quality-sparkline--empty"
        data-testid="quality-sparkline"
        width={width}
        height={height}
        role="img"
        aria-label="No quality history available"
      />
    )
  }

  const scores = trimmed.map((point) => point.score)
  const maxScore = Math.max(...scores, 100)
  const minScore = Math.min(...scores, 0)
  const range = Math.max(1, maxScore - minScore)
  const stepX = trimmed.length > 1 ? width / (trimmed.length - 1) : 0

  const coords = trimmed.map((point, index) => {
    const x = trimmed.length === 1 ? width / 2 : index * stepX
    const yNormalized = (point.score - minScore) / range
    const y = height - yNormalized * height
    return { x, y, point }
  })

  const path = coords.map(({ x, y }, index) => `${index === 0 ? 'M' : 'L'}${x.toFixed(2)},${y.toFixed(2)}`).join(' ')

  return (
    <svg
      className="quality-sparkline"
      data-testid="quality-sparkline"
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-label={`Quality trend over last ${trimmed.length} runs`}
    >
      {coords.length > 1 ? (
        <path d={path} fill="none" stroke={strokeColor} strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />
      ) : null}
      {coords.map(({ x, y, point }, index) => (
        <circle
          key={`${point.timestamp}-${index}`}
          data-testid="quality-sparkline-point"
          cx={x}
          cy={y}
          r={2.5}
          fill={strokeColor}
        />
      ))}
    </svg>
  )
}

async function fetchQuality(
  engagementId: string,
  token: string | null | undefined,
  signal: AbortSignal,
): Promise<QualitySnapshot> {
  const headers: HeadersInit = token ? { Authorization: `Bearer ${token}` } : {}
  const response = await fetch(`/api/engagements/${encodeURIComponent(engagementId)}/quality`, {
    signal,
    headers,
  })
  if (!response.ok) {
    throw new Error(`quality fetch failed: ${response.status}`)
  }
  return (await response.json()) as QualitySnapshot
}

function resolveWebSocketUrl(engagementId: string): string | null {
  if (typeof window === 'undefined') {
    return null
  }
  const { protocol, host } = window.location
  if (!/^https?:$/.test(protocol)) {
    return null
  }
  const wsProto = protocol === 'https:' ? 'wss:' : 'ws:'
  return `${wsProto}//${host}/ws/progress?engagement_id=${encodeURIComponent(engagementId)}`
}

type QualityUpdatedEvent = {
  event?: string
  type?: string
  engagement_id?: string | number
  snapshot?: QualitySnapshot
}

function isQualityUpdatedEvent(payload: unknown): payload is QualityUpdatedEvent {
  if (typeof payload !== 'object' || payload === null) {
    return false
  }
  const record = payload as Record<string, unknown>
  const eventName = record.event ?? record.type
  return eventName === 'quality:updated'
}

export type QualityWidgetProps = {
  engagementId: string
  authToken?: string | null
  /** Injectable fetcher for tests. Defaults to the real fetch path. */
  fetcher?: (engagementId: string, signal: AbortSignal) => Promise<QualitySnapshot>
  /** Optional pre-supplied initial snapshot (skips loading state). */
  initialSnapshot?: QualitySnapshot
  /** Optional WebSocket factory for tests; skipped in non-browser envs. */
  socketFactory?: (url: string) => WebSocket
  /** Disable WebSocket subscription (defaults to enabled). */
  disableWebSocket?: boolean
}

export default function QualityWidget({
  engagementId,
  authToken,
  fetcher,
  initialSnapshot,
  socketFactory,
  disableWebSocket = false,
}: QualityWidgetProps) {
  const [snapshot, setSnapshot] = useState<QualitySnapshot | null>(initialSnapshot ?? null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState<boolean>(initialSnapshot === undefined)
  const mountedRef = useRef(true)

  const effectiveFetcher = useCallback(
    (id: string, signal: AbortSignal) => {
      if (fetcher) {
        return fetcher(id, signal)
      }
      return fetchQuality(id, authToken, signal)
    },
    [fetcher, authToken],
  )

  const load = useCallback(
    async (signal: AbortSignal) => {
      setError(null)
      setLoading(true)
      try {
        const next = await effectiveFetcher(engagementId, signal)
        if (!signal.aborted && mountedRef.current) {
          setSnapshot(next)
        }
      } catch (fetchError) {
        if (signal.aborted || !mountedRef.current) {
          return
        }
        setError(fetchError instanceof Error ? fetchError.message : 'quality unavailable')
      } finally {
        if (!signal.aborted && mountedRef.current) {
          setLoading(false)
        }
      }
    },
    [effectiveFetcher, engagementId],
  )

  useEffect(() => {
    mountedRef.current = true
    const controller = new AbortController()
    // Non-blocking: render loading state immediately, do not await.
    void load(controller.signal)
    return () => {
      mountedRef.current = false
      controller.abort()
    }
  }, [load])

  // Synchronize snapshot state when initialSnapshot prop changes
  useEffect(() => {
    if (initialSnapshot !== undefined) {
      setSnapshot(initialSnapshot)
      setError(null)
      setLoading(false)
    }
  }, [initialSnapshot])
  // WebSocket auto-refresh on `quality:updated`.
  useEffect(() => {
    if (disableWebSocket) {
      return
    }
    const url = resolveWebSocketUrl(engagementId)
    if (!url && !socketFactory) {
      return
    }
    let socket: WebSocket
    try {
      socket = socketFactory ? socketFactory(url ?? '') : new WebSocket(url as string)
    } catch {
      return
    }

    const handleMessage = (event: MessageEvent) => {
      let payload: unknown
      try {
        payload = typeof event.data === 'string' ? JSON.parse(event.data) : event.data
      } catch {
        return
      }
      if (!isQualityUpdatedEvent(payload)) {
        return
      }
      const eventEngagement = payload.engagement_id
      if (eventEngagement !== undefined && String(eventEngagement) !== String(engagementId)) {
        return
      }
      if (payload.snapshot) {
        setSnapshot(payload.snapshot)
        setError(null)
        setLoading(false)
        return
      }
      const controller = new AbortController()
      void load(controller.signal)
    }

    socket.addEventListener('message', handleMessage)
    return () => {
      socket.removeEventListener('message', handleMessage)
      try {
        socket.close()
      } catch {
        // swallow: socket may already be closed
      }
    }
  }, [engagementId, disableWebSocket, socketFactory, load])

  const overallScore = snapshot?.overall_score ?? 0
  const threshold = classifyScore(overallScore)
  const metrics = useMemo(() => normalizeMetrics(snapshot?.metrics ?? []), [snapshot])
  const history = useMemo(() => lastFive(snapshot?.history ?? []), [snapshot])

  if (loading && !snapshot) {
    return (
      <section className="quality-widget quality-widget--loading" data-testid="quality-widget-loading" aria-busy="true">
        <header className="quality-widget-header">
          <h3>Data quality</h3>
        </header>
        <p className="muted-copy">Loading quality snapshot…</p>
      </section>
    )
  }

  if (error && !snapshot) {
    return (
      <section className="quality-widget quality-widget--error" data-testid="quality-widget-error" role="alert">
        <header className="quality-widget-header">
          <h3>Data quality</h3>
        </header>
        <p className="notice">Quality data unavailable: {error}</p>
      </section>
    )
  }

  return (
    <section className="quality-widget" data-testid="quality-widget">
      <header className="quality-widget-header">
        <h3>Data quality</h3>
        {snapshot?.generated_at ? (
          <span className="quality-widget-generated muted-copy">Updated {snapshot.generated_at}</span>
        ) : null}
      </header>

      <div className="quality-widget-body">
        <div className="quality-score" data-testid="quality-score">
          <span
            className={`quality-score-value quality-score-value--${threshold}`}
            data-testid="quality-score-value"
            style={{ color: thresholdColor(threshold) }}
          >
            {Math.round(overallScore)}
          </span>
          <span className="quality-score-indicator" data-testid="quality-score-indicator" aria-label={`Threshold ${threshold}`}>
            {thresholdIcon(threshold)}
          </span>
        </div>

        <div className="quality-sparkline-wrap" data-testid="quality-sparkline-wrap">
          <Sparkline points={history} strokeColor={thresholdColor(threshold)} />
          <span className="muted-copy quality-sparkline-caption">Last {history.length} run{history.length === 1 ? '' : 's'}</span>
        </div>
      </div>

      <table className="quality-metrics" data-testid="quality-metrics-table">
        <thead>
          <tr>
            <th scope="col">Metric</th>
            <th scope="col">Score</th>
            <th scope="col">Health</th>
          </tr>
        </thead>
        <tbody>
          {metrics.map((metric) => {
            const metricThreshold = classifyScore(metric.score)
            return (
              <tr key={metric.key} data-testid={`quality-metric-row-${metric.key}`}>
                <th scope="row">{metric.label}</th>
                <td data-testid={`quality-metric-score-${metric.key}`}>{Math.round(metric.score)}</td>
                <td data-testid={`quality-metric-indicator-${metric.key}`} aria-label={`${metric.label} threshold ${metricThreshold}`}>
                  {thresholdIcon(metricThreshold)}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>

      {error ? (
        <p className="notice quality-widget-inline-error" data-testid="quality-widget-inline-error">
          Last refresh failed: {error}
        </p>
      ) : null}
    </section>
  )
}
