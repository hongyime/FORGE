import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react'

import {
  ArtifactStatusTab,
  type ArtifactQueueResponse,
  type ArtifactQueueRow,
} from './ArtifactStatusTab'
import { formatRelativeTime, pageWindow } from './artifact-status-utils'

const FROZEN_NOW = new Date('2026-09-01T12:00:00Z')
const now = () => new Date(FROZEN_NOW)

function makeRow(overrides: Partial<ArtifactQueueRow> = {}): ArtifactQueueRow {
  return {
    id: overrides.id ?? 1,
    artifact_name: overrides.artifact_name ?? 'sample.apk',
    parser: overrides.parser ?? 'apk_static',
    state: overrides.state ?? 'complete',
    timestamp: overrides.timestamp ?? '2026-09-01T11:59:30Z',
    error_msg: overrides.error_msg ?? null,
  }
}

function makeResponse(
  items: ArtifactQueueRow[],
  overrides: Partial<ArtifactQueueResponse> = {},
): ArtifactQueueResponse {
  return {
    items,
    page: overrides.page ?? 1,
    page_size: overrides.page_size ?? 25,
    total: overrides.total ?? items.length,
    total_pages: overrides.total_pages ?? 1,
    generated_at: overrides.generated_at ?? '2026-09-01T12:00:00Z',
  }
}

function mockFetcher(payload: ArtifactQueueResponse) {
  return vi.fn(async () => ({
    ok: true,
    status: 200,
    json: async () => payload,
  })) as unknown as typeof fetch
}

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

describe('formatRelativeTime', () => {
  it('formats seconds/minutes/hours/days consistently', () => {
    const nowD = new Date('2026-09-01T12:00:00Z')
    expect(formatRelativeTime('2026-09-01T11:59:58Z', nowD)).toBe('just now')
    expect(formatRelativeTime('2026-09-01T11:59:30Z', nowD)).toMatch(/30s ago/)
    expect(formatRelativeTime('2026-09-01T11:30:00Z', nowD)).toMatch(/30m ago/)
    expect(formatRelativeTime('2026-09-01T09:00:00Z', nowD)).toMatch(/3h ago/)
    expect(formatRelativeTime('2026-08-30T12:00:00Z', nowD)).toMatch(/2d ago/)
  })
})

describe('pageWindow', () => {
  it('shows first/last/current/neighbors and collapses the rest', () => {
    expect(pageWindow(1, 1)).toEqual([1])
    expect(pageWindow(1, 3)).toEqual([1, 2, 3])
    expect(pageWindow(5, 10)).toEqual([1, 'gap', 4, 5, 6, 'gap', 10])
    expect(pageWindow(1, 10)).toEqual([1, 2, 'gap', 10])
    expect(pageWindow(10, 10)).toEqual([1, 'gap', 9, 10])
  })
})

describe('<ArtifactStatusTab />', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(FROZEN_NOW)
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('renders the table with mocked queue data (10 artifacts)', async () => {
    const rows = Array.from({ length: 10 }).map((_, index) =>
      makeRow({
        id: index + 1,
        artifact_name: `artifact-${index + 1}.bin`,
        parser: index % 2 === 0 ? 'binary_static' : 'apk_static',
        state: index === 0 ? 'failed' : 'complete',
        error_msg: index === 0 ? 'boom: parser crashed on offset 0x00' : null,
        timestamp: '2026-09-01T11:59:30Z',
      }),
    )
    const fetcher = mockFetcher(
      makeResponse(rows, { total: 10, total_pages: 1, page: 1 }),
    )

    render(
      <ArtifactStatusTab
        engagementId="1001"
        fetcher={fetcher}
        now={now}
        refreshIntervalMs={0}
      />,
    )

    // Flush the initial fetch microtask/promise chain under fake timers.
    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })

    // Every mocked row is rendered.
    for (let index = 0; index < 10; index += 1) {
      expect(
        screen.getByTestId(`artifact-row-${index + 1}`),
      ).toBeInTheDocument()
    }

    // Failed row is not hidden and has expand affordance.
    const failedRow = screen.getByTestId('artifact-row-1')
    expect(failedRow).toHaveAttribute('data-state', 'failed')
    expect(
      within(failedRow).getByTestId('artifact-row-1-toggle'),
    ).toBeInTheDocument()

    // The fetch went to the correct URL.
    const call = (fetcher as unknown as { mock: { calls: unknown[][] } }).mock.calls[0]
    expect(call[0]).toContain('/api/engagements/1001/artifact-queue')
    expect(call[0]).toContain('page=1')
    expect(call[0]).toContain('page_size=25')
  })

  it('filter dropdown re-requests with state param and resets to page 1', async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () =>
          makeResponse(
            Array.from({ length: 3 }).map((_, i) =>
              makeRow({ id: i + 1, state: 'complete' }),
            ),
          ),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () =>
          makeResponse([makeRow({ id: 42, state: 'failed', error_msg: 'x' })], {
            total: 1,
            total_pages: 1,
          }),
      }) as unknown as typeof fetch

    render(
      <ArtifactStatusTab
        engagementId="1001"
        fetcher={fetcher}
        now={now}
        refreshIntervalMs={0}
      />,
    )
    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })

    const select = screen.getByLabelText('Filter artifacts by state')
    fireEvent.change(select, { target: { value: 'failed' } })

    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })

    const calls = (fetcher as unknown as { mock: { calls: string[][] } }).mock.calls
    expect(calls.length).toBe(2)
    expect(calls[1][0]).toContain('state=failed')
    expect(calls[1][0]).toContain('page=1')

    expect(screen.getByTestId('artifact-row-42')).toBeInTheDocument()
  })

  it('pagination next/prev updates page param', async () => {
    const firstPage = makeResponse(
      Array.from({ length: 25 }).map((_, i) => makeRow({ id: i + 1 })),
      { total: 50, total_pages: 2, page: 1 },
    )
    const secondPage = makeResponse(
      Array.from({ length: 25 }).map((_, i) => makeRow({ id: i + 26 })),
      { total: 50, total_pages: 2, page: 2 },
    )
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => firstPage })
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => secondPage })
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => firstPage }) as unknown as typeof fetch

    render(
      <ArtifactStatusTab
        engagementId="1001"
        fetcher={fetcher}
        now={now}
        refreshIntervalMs={0}
      />,
    )
    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })

    fireEvent.click(screen.getByRole('button', { name: /next page/i }))
    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })

    const calls = (fetcher as unknown as { mock: { calls: string[][] } }).mock.calls
    expect(calls[1][0]).toContain('page=2')

    fireEvent.click(screen.getByRole('button', { name: /previous page/i }))
    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })
    expect(calls[2][0]).toContain('page=1')
  })

  it('error rows are expandable via keyboard-accessible button', async () => {
    const fetcher = mockFetcher(
      makeResponse([
        makeRow({
          id: 7,
          state: 'failed',
          error_msg: 'ZipError: bad central directory at offset 0x1234',
        }),
      ]),
    )
    render(
      <ArtifactStatusTab
        engagementId="1001"
        fetcher={fetcher}
        now={now}
        refreshIntervalMs={0}
      />,
    )
    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })

    const toggle = screen.getByTestId('artifact-row-7-toggle')
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByTestId('artifact-row-7-error-panel')).not.toBeInTheDocument()

    fireEvent.click(toggle)

    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    const panel = screen.getByTestId('artifact-row-7-error-panel')
    expect(panel).toHaveTextContent('ZipError: bad central directory')
  })

  it('shows skeleton rows during initial load', () => {
    // Never-resolving fetch => stays in the "loading" state.
    const fetcher = vi.fn(() => new Promise(() => {})) as unknown as typeof fetch
    render(
      <ArtifactStatusTab
        engagementId="1001"
        fetcher={fetcher}
        now={now}
        refreshIntervalMs={0}
      />,
    )
    expect(screen.getAllByTestId('artifact-skeleton-row').length).toBeGreaterThan(0)
  })

  it('surfaces API errors with a retry button', async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce({ ok: false, status: 503, json: async () => ({}) })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => makeResponse([makeRow({ id: 99 })]),
      }) as unknown as typeof fetch

    render(
      <ArtifactStatusTab
        engagementId="1001"
        fetcher={fetcher}
        now={now}
        refreshIntervalMs={0}
      />,
    )
    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })

    const banner = screen.getByTestId('artifact-error-banner')
    expect(banner).toHaveTextContent(/503/)

    fireEvent.click(within(banner).getByRole('button', { name: /retry/i }))
    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })

    expect(screen.getByTestId('artifact-row-99')).toBeInTheDocument()
  })

  it('shows a user-visible "last updated" indicator', async () => {
    const fetcher = mockFetcher(makeResponse([makeRow({ id: 1 })]))
    render(
      <ArtifactStatusTab
        engagementId="1001"
        fetcher={fetcher}
        now={now}
        refreshIntervalMs={0}
      />,
    )
    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })

    expect(screen.getByTestId('artifact-last-updated')).toHaveTextContent(
      /Last updated/,
    )
  })
})
