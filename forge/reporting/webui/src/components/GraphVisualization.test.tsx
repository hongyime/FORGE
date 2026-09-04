import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import {
  GraphVisualization,
  type GraphPayload,
  type GraphologyFactory,
  type GraphologyLike,
  type GraphologyNodeAttributes,
  type SigmaFactory,
  type SigmaLike,
  type SigmaLoader,
} from './GraphVisualization'
import {
  circularLayout,
  colorForNodeType,
  edgeEndpoints,
  forceLayout,
  hierarchicalLayout,
  nodeKey,
  nodeLabelOf,
  nodeTypeOf,
} from './graph-visualization-utils'

// ---------------------------------------------------------------------------
// Sigma / graphology stubs
// ---------------------------------------------------------------------------

type ClickHandler = (payload: { node?: string; edge?: string }) => void

class StubGraph implements GraphologyLike {
  private nodeMap = new Map<string, GraphologyNodeAttributes>()
  private edgeMap = new Map<string, { source: string; target: string; attrs: GraphologyNodeAttributes }>()
  order = 0

  addNode(key: string, attributes: GraphologyNodeAttributes = {}) {
    if (this.nodeMap.has(key)) throw new Error(`node exists: ${key}`)
    this.nodeMap.set(key, { ...attributes })
    this.order = this.nodeMap.size
  }
  addEdge(source: string, target: string, attributes: GraphologyNodeAttributes = {}) {
    const key = `${source}->${target}`
    this.edgeMap.set(key, { source, target, attrs: { ...attributes } })
  }
  addEdgeWithKey(key: string, source: string, target: string, attributes: GraphologyNodeAttributes = {}) {
    this.edgeMap.set(key, { source, target, attrs: { ...attributes } })
  }
  hasNode(key: string) {
    return this.nodeMap.has(key)
  }
  hasEdge(source: string, target: string) {
    for (const value of this.edgeMap.values()) {
      if (value.source === source && value.target === target) return true
    }
    return false
  }
  setNodeAttribute(key: string, name: string, value: unknown) {
    const attrs = this.nodeMap.get(key)
    if (!attrs) throw new Error(`missing node: ${key}`)
    attrs[name] = value
  }
  getNodeAttribute(key: string, name: string) {
    return this.nodeMap.get(key)?.[name]
  }
  forEachNode(cb: (key: string, attrs: GraphologyNodeAttributes) => void) {
    this.nodeMap.forEach((attrs, key) => cb(key, attrs))
  }
  forEachEdge(
    cb: (key: string, attrs: GraphologyNodeAttributes, source: string, target: string) => void,
  ) {
    this.edgeMap.forEach((value, key) => cb(key, value.attrs, value.source, value.target))
  }
  nodes() {
    return [...this.nodeMap.keys()]
  }
  edges() {
    return [...this.edgeMap.keys()]
  }
  clear() {
    this.nodeMap.clear()
    this.edgeMap.clear()
    this.order = 0
  }
}

class StubSigma implements SigmaLike {
  private handlers = new Map<string, ClickHandler[]>()
  private cameraState = { x: 0, y: 0, ratio: 1, angle: 0 }
  private zoomCalls = 0
  private unzoomCalls = 0
  killed = false

  private graph: GraphologyLike

  constructor(graph: GraphologyLike) {
    this.graph = graph
  }

  getCamera() {
    return {
      animatedZoom: () => {
        this.zoomCalls += 1
      },
      animatedUnzoom: () => {
        this.unzoomCalls += 1
      },
      setState: (state: Partial<typeof this.cameraState>) => {
        this.cameraState = { ...this.cameraState, ...state }
      },
      getState: () => ({ ...this.cameraState }),
    }
  }
  on(event: string, handler: ClickHandler) {
    const bucket = this.handlers.get(event) ?? []
    bucket.push(handler)
    this.handlers.set(event, bucket)
  }
  emit(event: string, payload: { node?: string; edge?: string }) {
    const bucket = this.handlers.get(event) ?? []
    for (const h of bucket) h(payload)
  }
  refresh() {}
  resize() {}
  kill() {
    this.killed = true
  }
  getGraph() {
    return this.graph
  }
  // test helpers
  get camera() {
    return this.cameraState
  }
  get zoomCount() {
    return this.zoomCalls
  }
  get unzoomCount() {
    return this.unzoomCalls
  }
}

let lastSigma: StubSigma | null = null

const StubSigmaCtor = function (this: unknown, graph: GraphologyLike): StubSigma {
  const instance = new StubSigma(graph)
  lastSigma = instance
  return instance
} as unknown as SigmaFactory

const StubGraphCtor = function (this: unknown): StubGraph {
  return new StubGraph()
} as unknown as GraphologyFactory

const stubLoader: SigmaLoader = async () => ({
  Sigma: StubSigmaCtor,
  Graph: StubGraphCtor,
})

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const SAMPLE_GRAPH: GraphPayload = {
  nodes: [
    {
      node_id: 'HOST::app',
      node_type: 'HOST',
      label: 'app.acme.example',
      severity: 'MEDIUM',
      on_critical_path: true,
      metadata: { os_family: 'linux', service: 'web' },
    },
    {
      node_id: 'EMAIL::security',
      node_type: 'CREDENTIAL',
      label: 'security@acme.example',
      severity: 'LOW',
      metadata: {},
    },
    {
      node_id: 'CLOUD::bucket',
      node_type: 'CLOUD',
      label: 'storage bucket',
      severity: 'HIGH',
      on_critical_path: true,
      metadata: { provider: 'firebase' },
    },
  ],
  edges: [
    {
      source_node_id: 'HOST::app',
      target_node_id: 'CLOUD::bucket',
      edge_type: 'cloud_misconfig',
      on_critical_path: true,
    },
    {
      source_node_id: 'EMAIL::security',
      target_node_id: 'HOST::app',
      edge_type: 'credential_use',
    },
  ],
}

function mockFetcher(payload: GraphPayload) {
  return vi.fn(async () => ({
    ok: true,
    status: 200,
    json: async () => payload,
  })) as unknown as typeof fetch
}

// Flush any pending microtasks + effects after async loader resolves.
async function flushEffects() {
  await act(async () => {
    await Promise.resolve()
    await Promise.resolve()
  })
}

// ---------------------------------------------------------------------------
// Pure-helper tests
// ---------------------------------------------------------------------------

describe('graph helpers', () => {
  it('nodeKey prefers node_id then id then index fallback', () => {
    expect(nodeKey({ node_id: 'x' }, 0)).toBe('x')
    expect(nodeKey({ id: 'y' }, 0)).toBe('y')
    expect(nodeKey({}, 3)).toBe('node-3')
  })

  it('edgeEndpoints normalizes both key styles', () => {
    expect(edgeEndpoints({ source_node_id: 'a', target_node_id: 'b' })).toEqual({
      source: 'a',
      target: 'b',
    })
    expect(edgeEndpoints({ source: 'a', target: 'b' })).toEqual({
      source: 'a',
      target: 'b',
    })
    expect(edgeEndpoints({})).toBeNull()
  })

  it('nodeTypeOf uppercases and falls back to UNKNOWN', () => {
    expect(nodeTypeOf({ node_type: 'host' })).toBe('HOST')
    expect(nodeTypeOf({ entity_type: 'Cloud' })).toBe('CLOUD')
    expect(nodeTypeOf({})).toBe('UNKNOWN')
  })

  it('nodeLabelOf falls back to key when label missing', () => {
    expect(nodeLabelOf({ label: 'x' }, 'k')).toBe('x')
    expect(nodeLabelOf({}, 'k')).toBe('k')
  })

  it('colorForNodeType is stable and case-insensitive', () => {
    expect(colorForNodeType('HOST')).toBe(colorForNodeType('host'))
    expect(colorForNodeType('does-not-exist')).toBeTruthy()
  })

  it('circularLayout places nodes on a unit circle', () => {
    const pos = circularLayout(['a', 'b', 'c', 'd'])
    for (const key of ['a', 'b', 'c', 'd']) {
      const p = pos[key]
      const r = Math.sqrt(p.x * p.x + p.y * p.y)
      expect(r).toBeCloseTo(1, 5)
    }
  })

  it('forceLayout is deterministic for same input', () => {
    const a = forceLayout(['a', 'b', 'c'], [{ source: 'a', target: 'b' }], 20)
    const b = forceLayout(['a', 'b', 'c'], [{ source: 'a', target: 'b' }], 20)
    expect(a).toEqual(b)
  })

  it('hierarchicalLayout groups by type into distinct layers', () => {
    const positions = hierarchicalLayout([
      { key: 'a', type: 'HOST' },
      { key: 'b', type: 'HOST' },
      { key: 'c', type: 'CLOUD' },
    ])
    // HOST and CLOUD must land on different y layers.
    expect(positions.a.y).not.toBe(positions.c.y)
    expect(positions.a.y).toBe(positions.b.y)
  })
})

// ---------------------------------------------------------------------------
// Component tests
// ---------------------------------------------------------------------------

describe('<GraphVisualization />', () => {
  beforeEach(() => {
    lastSigma = null
  })
  afterEach(() => {
    cleanup()
  })

  it('renders skeleton while scripts / data are loading, then the canvas', async () => {
    render(
      <GraphVisualization
        engagementId="1001"
        initialGraph={SAMPLE_GRAPH}
        sigmaLoader={stubLoader}
      />,
    )
    // Canvas is always in the tree; skeleton is only visible while loading.
    expect(screen.getByTestId('graph-canvas')).toBeInTheDocument()
    // After the loader resolves, sigma is constructed.
    await flushEffects()
    expect(lastSigma).not.toBeNull()
  })

  it('fetches from the asset-graph endpoint using engagement id and token', async () => {
    const fetcher = mockFetcher(SAMPLE_GRAPH)
    render(
      <GraphVisualization
        engagementId="42"
        token="tok-abc"
        fetcher={fetcher}
        sigmaLoader={stubLoader}
      />,
    )
    await flushEffects()
    expect(fetcher).toHaveBeenCalledWith(
      '/api/engagements/42/asset-graph',
      expect.objectContaining({
        headers: expect.objectContaining({ Authorization: 'Bearer tok-abc' }),
      }),
    )
  })

  it('renders the legend with node-type entries derived from data', async () => {
    render(
      <GraphVisualization
        engagementId="1"
        initialGraph={SAMPLE_GRAPH}
        sigmaLoader={stubLoader}
      />,
    )
    await flushEffects()
    const legend = screen.getByTestId('graph-legend')
    expect(within(legend).getByText('HOST')).toBeInTheDocument()
    expect(within(legend).getByText('CLOUD')).toBeInTheDocument()
    expect(within(legend).getByText('CREDENTIAL')).toBeInTheDocument()
  })

  it('shows details panel when a node is clicked', async () => {
    render(
      <GraphVisualization
        engagementId="1"
        initialGraph={SAMPLE_GRAPH}
        sigmaLoader={stubLoader}
      />,
    )
    await flushEffects()
    // Simulate sigma's clickNode event.
    act(() => {
      lastSigma?.emit('clickNode', { node: 'HOST::app' })
    })
    const panel = screen.getByTestId('graph-details-panel')
    expect(within(panel).getByRole('heading', { name: 'app.acme.example' })).toBeInTheDocument()
    expect(within(panel).getByTestId('graph-details-type')).toHaveTextContent('HOST')
    // Incident edges include both edges touching HOST::app.
    expect(within(panel).getByTestId('graph-details-edges').children.length).toBe(2)
  })

  it('closes the details panel via Escape and via the close button', async () => {
    render(
      <GraphVisualization
        engagementId="1"
        initialGraph={SAMPLE_GRAPH}
        sigmaLoader={stubLoader}
      />,
    )
    await flushEffects()
    act(() => lastSigma?.emit('clickNode', { node: 'HOST::app' }))
    expect(screen.getByTestId('graph-details-panel')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('graph-details-close'))
    expect(screen.queryByTestId('graph-details-panel')).toBeNull()

    // Reopen, close with Escape.
    act(() => lastSigma?.emit('clickNode', { node: 'HOST::app' }))
    fireEvent.keyDown(screen.getByTestId('graph-canvas'), { key: 'Escape' })
    expect(screen.queryByTestId('graph-details-panel')).toBeNull()
  })

  it('zoom in / out buttons drive the sigma camera', async () => {
    render(
      <GraphVisualization
        engagementId="1"
        initialGraph={SAMPLE_GRAPH}
        sigmaLoader={stubLoader}
      />,
    )
    await flushEffects()
    const user = userEvent.setup()
    await user.click(screen.getByTestId('graph-zoom-in'))
    await user.click(screen.getByTestId('graph-zoom-in'))
    await user.click(screen.getByTestId('graph-zoom-out'))
    expect(lastSigma?.zoomCount).toBe(2)
    expect(lastSigma?.unzoomCount).toBe(1)
  })

  it('keyboard "+" and "-" zoom, arrow keys pan the camera', async () => {
    render(
      <GraphVisualization
        engagementId="1"
        initialGraph={SAMPLE_GRAPH}
        sigmaLoader={stubLoader}
      />,
    )
    await flushEffects()
    const canvas = screen.getByTestId('graph-canvas')
    fireEvent.keyDown(canvas, { key: '+' })
    expect(lastSigma?.zoomCount).toBe(1)
    fireEvent.keyDown(canvas, { key: '-' })
    expect(lastSigma?.unzoomCount).toBe(1)

    const startX = lastSigma?.camera.x ?? 0
    fireEvent.keyDown(canvas, { key: 'ArrowRight' })
    expect(lastSigma?.camera.x).not.toBe(startX)
  })

  it('layout selector re-lays-out the graph without destroying sigma', async () => {
    render(
      <GraphVisualization
        engagementId="1"
        initialGraph={SAMPLE_GRAPH}
        sigmaLoader={stubLoader}
        initialLayout="circular"
      />,
    )
    await flushEffects()
    const originalSigma = lastSigma
    const select = screen.getByTestId('graph-layout-select') as HTMLSelectElement
    fireEvent.change(select, { target: { value: 'hierarchical' } })
    await flushEffects()
    // Same sigma instance is reused; kill() is only called on unmount / rebuild.
    expect(lastSigma).toBe(originalSigma)
    expect(originalSigma?.killed).toBe(false)
    // Node positions were rewritten for the new layout.
    const graph = originalSigma?.getGraph()
    const yValues = new Set<number>()
    graph?.forEachNode((_key, attrs) => {
      yValues.add(Number(attrs.y))
    })
    expect(yValues.size).toBeGreaterThan(1)
  })

  it('search filter hides non-matching nodes', async () => {
    render(
      <GraphVisualization
        engagementId="1"
        initialGraph={SAMPLE_GRAPH}
        sigmaLoader={stubLoader}
      />,
    )
    await flushEffects()
    const input = screen.getByTestId('graph-search-input') as HTMLInputElement
    fireEvent.change(input, { target: { value: 'bucket' } })
    await flushEffects()
    const graph = lastSigma?.getGraph()
    const visibility: Record<string, boolean> = {}
    graph?.forEachNode((key, attrs) => {
      visibility[key] = !attrs.hidden
    })
    expect(visibility['CLOUD::bucket']).toBe(true)
    expect(visibility['HOST::app']).toBe(false)
    expect(visibility['EMAIL::security']).toBe(false)
  })

  it('node-type filter narrows visible nodes', async () => {
    render(
      <GraphVisualization
        engagementId="1"
        initialGraph={SAMPLE_GRAPH}
        sigmaLoader={stubLoader}
      />,
    )
    await flushEffects()
    const filter = screen.getByTestId('graph-type-filter') as HTMLSelectElement
    fireEvent.change(filter, { target: { value: 'HOST' } })
    await flushEffects()
    const graph = lastSigma?.getGraph()
    const visibility: Record<string, boolean> = {}
    graph?.forEachNode((key, attrs) => {
      visibility[key] = !attrs.hidden
    })
    expect(visibility['HOST::app']).toBe(true)
    expect(visibility['CLOUD::bucket']).toBe(false)
  })

  it('renders an error banner when the fetch fails', async () => {
    const fetcher = vi.fn(async () => ({
      ok: false,
      status: 500,
      json: async () => ({}),
    })) as unknown as typeof fetch
    render(
      <GraphVisualization
        engagementId="1"
        fetcher={fetcher}
        sigmaLoader={stubLoader}
      />,
    )
    await flushEffects()
    expect(screen.getByTestId('graph-error-banner')).toBeInTheDocument()
  })

  it('does not hardcode the engagement id in the endpoint', async () => {
    const fetcher = mockFetcher(SAMPLE_GRAPH)
    render(
      <GraphVisualization
        engagementId="9999"
        fetcher={fetcher}
        sigmaLoader={stubLoader}
      />,
    )
    await flushEffects()
    const [url] = (fetcher as unknown as { mock: { calls: unknown[][] } }).mock.calls[0]
    expect(String(url)).toContain('/api/engagements/9999/asset-graph')
  })
})
