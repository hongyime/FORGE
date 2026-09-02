/**
 * QualityWidget tests - written for vitest + @testing-library/react.
 *
 * NOTE: forge/reporting/webui does not currently ship a test runner
 * (package.json has no `test` script and no vitest/@testing-library deps).
 * These tests are written against the vitest + testing-library idioms so
 * they run as soon as the runner is added via:
 *   npm i -D vitest @testing-library/react @testing-library/jest-dom jsdom
 * and package.json gets: "test": "vitest run --environment jsdom"
 */
import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import QualityWidget, {
  classifyScore,
  Sparkline,
  type QualitySnapshot,
} from './QualityWidget'

const MOCK_SNAPSHOT: QualitySnapshot = {
  engagement_id: '1001',
  overall_score: 87,
  generated_at: '2026-09-01 09:00:00',
  metrics: [
    { key: 'coverage', label: 'Coverage', score: 90 },
    { key: 'completeness', label: 'Completeness', score: 82 },
    { key: 'freshness', label: 'Freshness', score: 55 },
    { key: 'connectivity', label: 'Connectivity', score: 30 },
  ],
  history: [
    { timestamp: '2026-09-01T08:00:00Z', score: 70 },
    { timestamp: '2026-09-01T08:15:00Z', score: 75 },
    { timestamp: '2026-09-01T08:30:00Z', score: 80 },
    { timestamp: '2026-09-01T08:45:00Z', score: 85 },
    { timestamp: '2026-09-01T09:00:00Z', score: 87 },
  ],
}

describe('classifyScore', () => {
  it('returns good for scores at or above 80', () => {
    expect(classifyScore(80)).toBe('good')
    expect(classifyScore(100)).toBe('good')
  })
  it('returns warn for scores in [50, 80)', () => {
    expect(classifyScore(50)).toBe('warn')
    expect(classifyScore(79)).toBe('warn')
  })
  it('returns bad for scores below 50', () => {
    expect(classifyScore(49)).toBe('bad')
    expect(classifyScore(0)).toBe('bad')
  })
})

describe('Sparkline', () => {
  it('renders exactly one point per history entry', () => {
    render(<Sparkline points={MOCK_SNAPSHOT.history} />)
    const points = screen.getAllByTestId('quality-sparkline-point')
    expect(points).toHaveLength(5)
  })

  it('renders empty svg when no points', () => {
    render(<Sparkline points={[]} />)
    const svg = screen.getByTestId('quality-sparkline')
    expect(svg).toBeInTheDocument()
    expect(svg.getAttribute('aria-label')).toContain('No quality history')
  })

  it('caps at last 5 points when given more', () => {
    const many = Array.from({ length: 8 }, (_, i) => ({
      timestamp: `2026-09-01T0${i}:00:00Z`,
      score: 50 + i,
    }))
    render(<Sparkline points={many} />)
    expect(screen.getAllByTestId('quality-sparkline-point')).toHaveLength(5)
  })
})

describe('QualityWidget', () => {
  it('renders widget with mock quality data via initialSnapshot', () => {
    render(
      <QualityWidget
        engagementId="1001"
        initialSnapshot={MOCK_SNAPSHOT}
        disableWebSocket
      />,
    )
    expect(screen.getByTestId('quality-widget')).toBeInTheDocument()
    expect(screen.getByTestId('quality-score-value')).toHaveTextContent('87')
  })

  it('color indicator matches score threshold (good → 🟢)', () => {
    render(
      <QualityWidget
        engagementId="1001"
        initialSnapshot={MOCK_SNAPSHOT}
        disableWebSocket
      />,
    )
    expect(screen.getByTestId('quality-score-indicator')).toHaveTextContent('🟢')
  })

  it('color indicator degrades for warn and bad scores', () => {
    const warnSnapshot: QualitySnapshot = { ...MOCK_SNAPSHOT, overall_score: 60 }
    const { rerender } = render(
      <QualityWidget engagementId="1001" initialSnapshot={warnSnapshot} disableWebSocket />,
    )
    expect(screen.getByTestId('quality-score-indicator')).toHaveTextContent('🟡')

    const badSnapshot: QualitySnapshot = { ...MOCK_SNAPSHOT, overall_score: 30 }
    rerender(<QualityWidget engagementId="1001" initialSnapshot={badSnapshot} disableWebSocket />)
    expect(screen.getByTestId('quality-score-indicator')).toHaveTextContent('🔴')
  })

  it('sparkline shows 5 data points', () => {
    render(
      <QualityWidget
        engagementId="1001"
        initialSnapshot={MOCK_SNAPSHOT}
        disableWebSocket
      />,
    )
    expect(screen.getAllByTestId('quality-sparkline-point')).toHaveLength(5)
  })

  it('table shows all 4 metrics in canonical order', () => {
    render(
      <QualityWidget
        engagementId="1001"
        initialSnapshot={MOCK_SNAPSHOT}
        disableWebSocket
      />,
    )
    expect(screen.getByTestId('quality-metric-row-coverage')).toBeInTheDocument()
    expect(screen.getByTestId('quality-metric-row-completeness')).toBeInTheDocument()
    expect(screen.getByTestId('quality-metric-row-freshness')).toBeInTheDocument()
    expect(screen.getByTestId('quality-metric-row-connectivity')).toBeInTheDocument()

    expect(screen.getByTestId('quality-metric-score-coverage')).toHaveTextContent('90')
    expect(screen.getByTestId('quality-metric-indicator-freshness')).toHaveTextContent('🟡')
    expect(screen.getByTestId('quality-metric-indicator-connectivity')).toHaveTextContent('🔴')
  })

  it('renders loading state before fetch resolves', () => {
    const fetcher = vi.fn(
      () =>
        new Promise<QualitySnapshot>((resolve) => {
          // never resolves during this test tick
          setTimeout(() => resolve(MOCK_SNAPSHOT), 10_000)
        }),
    )
    render(<QualityWidget engagementId="1001" fetcher={fetcher} disableWebSocket />)
    expect(screen.getByTestId('quality-widget-loading')).toBeInTheDocument()
  })

  it('renders error state on API failure', async () => {
    const fetcher = vi.fn(() => Promise.reject(new Error('boom 500')))
    render(<QualityWidget engagementId="1001" fetcher={fetcher} disableWebSocket />)
    await waitFor(() => {
      expect(screen.getByTestId('quality-widget-error')).toBeInTheDocument()
    })
    expect(screen.getByTestId('quality-widget-error')).toHaveTextContent('boom 500')
  })

  it('resolves fetch and shows snapshot', async () => {
    const fetcher = vi.fn(() => Promise.resolve(MOCK_SNAPSHOT))
    render(<QualityWidget engagementId="1001" fetcher={fetcher} disableWebSocket />)
    await waitFor(() => {
      expect(screen.getByTestId('quality-widget')).toBeInTheDocument()
    })
    expect(fetcher).toHaveBeenCalledTimes(1)
    expect(screen.getByTestId('quality-score-value')).toHaveTextContent('87')
  })

  it('does not hardcode engagement id in fetch URL', async () => {
    const fetcher = vi.fn((id: string) => {
      expect(id).toBe('42-my-engagement')
      return Promise.resolve({ ...MOCK_SNAPSHOT, engagement_id: id })
    })
    render(<QualityWidget engagementId="42-my-engagement" fetcher={fetcher} disableWebSocket />)
    await waitFor(() => expect(fetcher).toHaveBeenCalled())
  })
})
