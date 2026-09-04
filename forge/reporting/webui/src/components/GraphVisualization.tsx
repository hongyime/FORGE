import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type KeyboardEvent,
} from 'react'
import {
  circularLayout,
  colorForNodeType,
  defaultSigmaLoader,
  edgeEndpoints,
  forceLayout,
  hierarchicalLayout,
  LAYOUT_KINDS,
  nodeKey,
  nodeLabelOf,
  NODE_TYPE_COLORS,
  nodeTypeOf,
} from './graph-visualization-utils'

/**
 * GraphVisualization
 *
 * Renders the engagement attack/asset graph using Sigma.js 2.x (vendored UMD)
 * plus graphology (vendored UMD). Fetches from
 * `/api/engagements/{engagementId}/asset-graph` (U5.2) by default; the
 * endpoint and fetcher are injectable for tests.
 *
 * Features:
 *   - Zoom (buttons, scroll, pinch), pan (drag, arrow keys)
 *   - Node click -> details panel with type, label, metadata, incident edges
 *   - Search + node-type filter
 *   - Layout selector: circular | force | hierarchical
 *   - Legend keyed on node_type
 *   - Loading skeleton until scripts + data resolve; no blocking on graph load
 *   - Touch: Sigma 2.x pinch-to-zoom + drag pan on touch surfaces
 *   - Keyboard: ArrowUp/Down/Left/Right pan, +/- zoom, Escape closes panel
 *
 * Sigma + graphology are consumed as UMD globals (window.Sigma /
 * window.graphology) because they are vendored under
 * `forge/webui/static/{sigma,graphology}/`. A loader is provided so tests
 * can inject stubs.
 *
 * Contract (U5.2):
 *   GET /api/engagements/{engagementId}/asset-graph
 *     -> { nodes: GraphNode[], edges: GraphEdge[], ... }
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type GraphNode = {
  node_id?: string
  id?: string
  label?: string
  node_type?: string
  entity_type?: string
  severity?: string
  source_table?: string
  source_id?: number | string
  on_critical_path?: boolean
  metadata?: Record<string, unknown>
}

export type GraphEdge = {
  source_node_id?: string
  target_node_id?: string
  source?: string
  target?: string
  label?: string
  edge_type?: string
  weight?: number
  on_critical_path?: boolean
  metadata?: Record<string, unknown>
}

export type GraphPayload = {
  nodes?: GraphNode[]
  edges?: GraphEdge[]
  critical_path_nodes?: string[]
  critical_path_weight?: number
  generated_at?: string
  source?: string
}

export type LayoutKind = 'circular' | 'force' | 'hierarchical'

/** Sigma 2.x + graphology surface actually used by this component. */
export type SigmaLike = {
  getCamera: () => {
    animatedZoom: (options?: { duration?: number; factor?: number }) => void
    animatedUnzoom: (options?: { duration?: number; factor?: number }) => void
    setState: (state: { x?: number; y?: number; ratio?: number; angle?: number }) => void
    getState: () => { x: number; y: number; ratio: number; angle: number }
  }
  on: (event: string, handler: (payload: { node?: string; edge?: string }) => void) => void
  refresh: () => void
  resize?: () => void
  kill: () => void
  getGraph: () => GraphologyLike
}

export type GraphologyNodeAttributes = Record<string, unknown>

export type GraphologyLike = {
  addNode: (key: string, attributes?: GraphologyNodeAttributes) => void
  addEdge: (source: string, target: string, attributes?: GraphologyNodeAttributes) => void
  addEdgeWithKey?: (
    key: string,
    source: string,
    target: string,
    attributes?: GraphologyNodeAttributes,
  ) => void
  hasNode: (key: string) => boolean
  hasEdge: (source: string, target: string) => boolean
  setNodeAttribute: (key: string, name: string, value: unknown) => void
  getNodeAttribute: (key: string, name: string) => unknown
  forEachNode: (callback: (key: string, attributes: GraphologyNodeAttributes) => void) => void
  forEachEdge: (
    callback: (
      key: string,
      attributes: GraphologyNodeAttributes,
      source: string,
      target: string,
    ) => void,
  ) => void
  nodes: () => string[]
  edges: () => string[]
  clear: () => void
  order: number
}

export type SigmaFactory = new (
  graph: GraphologyLike,
  container: HTMLElement,
  settings?: Record<string, unknown>,
) => SigmaLike

export type GraphologyFactory = new (
  settings?: Record<string, unknown>,
) => GraphologyLike

export type SigmaLoader = () => Promise<{
  Sigma: SigmaFactory
  Graph: GraphologyFactory
}>

export type GraphVisualizationProps = {
  engagementId: string | number
  /** Bearer token for authenticated live-mode fetches. */
  token?: string | null
  /** Injectable fetch for tests. Defaults to `window.fetch`. */
  fetcher?: typeof fetch
  /** Override the endpoint path (relative or absolute). */
  endpoint?: string
  /** Skip fetching and use this payload directly (tests). */
  initialGraph?: GraphPayload
  /** Injectable Sigma/graphology loader (tests). */
  sigmaLoader?: SigmaLoader
  /** Initial layout. Default 'force'. */
  initialLayout?: LayoutKind
  /** Optional external className / style hooks. */
  className?: string
  style?: CSSProperties
}

export type Position = { x: number; y: number }

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

type LoadState = 'idle' | 'loading-scripts' | 'loading-data' | 'ok' | 'error'

const KEYBOARD_PAN_STEP = 60 // pixels in camera state units
const KEYBOARD_ZOOM_FACTOR = 1.4

export function GraphVisualization(props: GraphVisualizationProps) {
  const {
    engagementId,
    token,
    fetcher,
    endpoint,
    initialGraph,
    sigmaLoader = defaultSigmaLoader,
    initialLayout = 'force',
    className,
    style,
  } = props

  const containerRef = useRef<HTMLDivElement | null>(null)
  const sigmaRef = useRef<SigmaLike | null>(null)
  const graphRef = useRef<GraphologyLike | null>(null)
  const factoriesRef = useRef<{ Sigma: SigmaFactory; Graph: GraphologyFactory } | null>(null)
  const layoutRef = useRef<LayoutKind>(initialLayout)

  const [graphData, setGraphData] = useState<GraphPayload | null>(initialGraph ?? null)
  const [loadState, setLoadState] = useState<LoadState>(initialGraph ? 'ok' : 'idle')
  const [errorMessage, setErrorMessage] = useState<string>('')
  const [layout, setLayout] = useState<LayoutKind>(initialLayout)
  const [factoriesReady, setFactoriesReady] = useState<boolean>(false)
  const [search, setSearch] = useState<string>('')
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)

  const doFetch =
    fetcher ?? (typeof window !== 'undefined' ? window.fetch.bind(window) : undefined)

  const resolvedEndpoint =
    endpoint ?? `/api/engagements/${encodeURIComponent(String(engagementId))}/asset-graph`

  // -------------------------------------------------------------------------
  // Data fetch
  // -------------------------------------------------------------------------

  useEffect(() => {
    if (initialGraph) {
      setGraphData(initialGraph)
      setLoadState('ok')
      return
    }
    if (!doFetch) {
      setLoadState('error')
      setErrorMessage('fetch is unavailable in this environment')
      return
    }
    const controller = new AbortController()
    setLoadState('loading-data')
    setErrorMessage('')
    void (async () => {
      try {
        const response = await doFetch(resolvedEndpoint, {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
          signal: controller.signal,
        })
        if (!response.ok) {
          throw new Error(`asset-graph fetch failed: ${response.status}`)
        }
        const payload = (await response.json()) as GraphPayload
        setGraphData(payload)
        setLoadState('ok')
      } catch (error) {
        if ((error as { name?: string }).name === 'AbortError') return
        setLoadState('error')
        setErrorMessage(
          error instanceof Error ? error.message : 'asset-graph fetch failed',
        )
      }
    })()
    return () => controller.abort()
  }, [doFetch, engagementId, initialGraph, resolvedEndpoint, token])

  // -------------------------------------------------------------------------
  // Sigma / graphology load
  // -------------------------------------------------------------------------

  useEffect(() => {
    let cancelled = false
    if (factoriesRef.current) return
    setLoadState((prev) => (prev === 'ok' ? prev : 'loading-scripts'))
    void (async () => {
      try {
        const factories = await sigmaLoader()
        if (cancelled) return
        factoriesRef.current = factories
        setFactoriesReady(true)
      } catch (error) {
        if (cancelled) return
        setLoadState('error')
        setErrorMessage(
          error instanceof Error ? error.message : 'failed to load sigma',
        )
      }
    })()
    return () => {
      cancelled = true
    }
  }, [sigmaLoader])

  // -------------------------------------------------------------------------
  // Build / rebuild the sigma instance when data is ready.
  // -------------------------------------------------------------------------

  const nodesByKey = useMemo(() => {
    const map = new Map<string, GraphNode>()
    if (!graphData?.nodes) return map
    graphData.nodes.forEach((node, index) => {
      map.set(nodeKey(node, index), node)
    })
    return map
  }, [graphData])

  const knownTypes = useMemo(() => {
    const set = new Set<string>()
    for (const node of nodesByKey.values()) set.add(nodeTypeOf(node))
    return [...set].sort()
  }, [nodesByKey])

  const rebuildGraph = useCallback(() => {
    const factories = factoriesRef.current
    const container = containerRef.current
    if (!factories || !container || !graphData) return

    // Kill existing sigma before replacing.
    if (sigmaRef.current) {
      sigmaRef.current.kill()
      sigmaRef.current = null
      graphRef.current = null
    }

    const graph = new factories.Graph({ multi: false, type: 'directed' })
    graphRef.current = graph

    const nodes = graphData.nodes ?? []
    const edges = graphData.edges ?? []

    const keys: string[] = []
    nodes.forEach((node, index) => {
      const key = nodeKey(node, index)
      keys.push(key)
      const type = nodeTypeOf(node)
      graph.addNode(key, {
        label: nodeLabelOf(node, key),
        color: colorForNodeType(type),
        size: node.on_critical_path ? 10 : 6,
        nodeType: type,
        severity: node.severity ?? '',
        raw: node,
        x: 0,
        y: 0,
      })
    })

    const normalizedEdges: Array<{ source: string; target: string }> = []
    edges.forEach((edge, index) => {
      const ends = edgeEndpoints(edge)
      if (!ends) return
      if (!graph.hasNode(ends.source) || !graph.hasNode(ends.target)) return
      normalizedEdges.push(ends)
      const attrs: GraphologyNodeAttributes = {
        label: edge.label ?? edge.edge_type ?? '',
        size: edge.on_critical_path ? 3 : 1,
        color: edge.on_critical_path ? '#ef4444' : '#94a3b8',
        raw: edge,
      }
      const edgeKey = `edge-${index}-${ends.source}-${ends.target}`
      if (graph.addEdgeWithKey) {
        try {
          graph.addEdgeWithKey(edgeKey, ends.source, ends.target, attrs)
        } catch {
          // Fallback if key already exists.
          if (!graph.hasEdge(ends.source, ends.target)) {
            graph.addEdge(ends.source, ends.target, attrs)
          }
        }
      } else if (!graph.hasEdge(ends.source, ends.target)) {
        graph.addEdge(ends.source, ends.target, attrs)
      }
    })

    // Apply initial layout positions.
    applyLayoutPositions(graph, keys, normalizedEdges, layoutRef.current, nodesByKey)

    const sigma = new factories.Sigma(graph, container, {
      allowInvalidContainer: true,
      renderEdgeLabels: false,
    })
    sigma.on('clickNode', (payload) => {
      if (typeof payload.node === 'string') {
        setSelectedNodeId(payload.node)
      }
    })
    sigma.on('clickStage', () => {
      setSelectedNodeId(null)
    })
    sigmaRef.current = sigma
    setLoadState('ok')
  }, [graphData, nodesByKey])

  // Rebuild on data/factory readiness.
  useEffect(() => {
    if (!graphData) return
    if (!factoriesReady) return
    rebuildGraph()
  }, [graphData, factoriesReady, rebuildGraph])

  // Cleanup on unmount.
  useEffect(() => {
    return () => {
      if (sigmaRef.current) {
        sigmaRef.current.kill()
        sigmaRef.current = null
        graphRef.current = null
      }
    }
  }, [])

  // -------------------------------------------------------------------------
  // Responsive: refresh sigma on container resize.
  // -------------------------------------------------------------------------

  useEffect(() => {
    const container = containerRef.current
    if (!container || typeof ResizeObserver === 'undefined') return
    const observer = new ResizeObserver(() => {
      const sigma = sigmaRef.current
      if (!sigma) return
      if (typeof sigma.resize === 'function') sigma.resize()
      sigma.refresh()
    })
    observer.observe(container)
    return () => observer.disconnect()
  }, [])

  // -------------------------------------------------------------------------
  // Layout switch: recompute positions without destroying sigma if possible.
  // -------------------------------------------------------------------------

  useEffect(() => {
    const graph = graphRef.current
    const sigma = sigmaRef.current
    if (!graph || !sigma) return
    const keys = graph.nodes()
    const edges: Array<{ source: string; target: string }> = []
    graph.forEachEdge((_key, _attrs, source, target) => {
      edges.push({ source, target })
    })
    applyLayoutPositions(graph, keys, edges, layout, nodesByKey)
    sigma.refresh()
  }, [layout, nodesByKey])

  // -------------------------------------------------------------------------
  // Search + type filter -> hidden attribute
  // -------------------------------------------------------------------------

  useEffect(() => {
    const graph = graphRef.current
    const sigma = sigmaRef.current
    if (!graph || !sigma) return
    const needle = search.trim().toLowerCase()
    graph.forEachNode((key, attrs) => {
      const label = String(attrs.label ?? key).toLowerCase()
      const nodeType = String(attrs.nodeType ?? 'UNKNOWN').toUpperCase()
      const matchesSearch = needle.length === 0 || label.includes(needle)
      const matchesType = typeFilter === 'all' || nodeType === typeFilter
      graph.setNodeAttribute(key, 'hidden', !(matchesSearch && matchesType))
    })
    sigma.refresh()
  }, [search, typeFilter, graphData])

  // -------------------------------------------------------------------------
  // Zoom / pan controls
  // -------------------------------------------------------------------------

  const zoomIn = useCallback(() => {
    sigmaRef.current?.getCamera().animatedZoom({ factor: KEYBOARD_ZOOM_FACTOR })
  }, [])

  const zoomOut = useCallback(() => {
    sigmaRef.current?.getCamera().animatedUnzoom({ factor: KEYBOARD_ZOOM_FACTOR })
  }, [])

  const panBy = useCallback((dx: number, dy: number) => {
    const camera = sigmaRef.current?.getCamera()
    if (!camera) return
    const state = camera.getState()
    // Camera x/y are in the [0..1]-ish sigma space; scale pan step down.
    camera.setState({
      x: state.x + dx * 0.002 * state.ratio,
      y: state.y + dy * 0.002 * state.ratio,
    })
  }, [])

  const onKeyDown = useCallback(
    (event: KeyboardEvent<HTMLDivElement>) => {
      switch (event.key) {
        case 'ArrowUp':
          event.preventDefault()
          panBy(0, -KEYBOARD_PAN_STEP)
          break
        case 'ArrowDown':
          event.preventDefault()
          panBy(0, KEYBOARD_PAN_STEP)
          break
        case 'ArrowLeft':
          event.preventDefault()
          panBy(-KEYBOARD_PAN_STEP, 0)
          break
        case 'ArrowRight':
          event.preventDefault()
          panBy(KEYBOARD_PAN_STEP, 0)
          break
        case '+':
        case '=':
          event.preventDefault()
          zoomIn()
          break
        case '-':
        case '_':
          event.preventDefault()
          zoomOut()
          break
        case 'Escape':
          setSelectedNodeId(null)
          break
        default:
          break
      }
    },
    [panBy, zoomIn, zoomOut],
  )

  // -------------------------------------------------------------------------
  // Details panel data
  // -------------------------------------------------------------------------

  const selectedDetail = useMemo(() => {
    if (!selectedNodeId) return null
    const node = nodesByKey.get(selectedNodeId)
    if (!node) return null
    const edges = (graphData?.edges ?? []).filter((edge) => {
      const ends = edgeEndpoints(edge)
      if (!ends) return false
      return ends.source === selectedNodeId || ends.target === selectedNodeId
    })
    return { key: selectedNodeId, node, edges }
  }, [selectedNodeId, nodesByKey, graphData])

  // -------------------------------------------------------------------------
  // Render
  // -------------------------------------------------------------------------

  const isLoading = loadState === 'loading-scripts' || loadState === 'loading-data'
  const showSkeleton = isLoading && !graphData

  // Update layoutRef during render so rebuildGraph sees current layout.
  layoutRef.current = layout

  const activeTypes = useMemo(() => {
    if (typeFilter === 'all') return knownTypes
    return knownTypes.filter((t) => t === typeFilter)
  }, [knownTypes, typeFilter])

  return (
    <section
      className={`panel graph-visualization ${className ?? ''}`.trim()}
      aria-label="Engagement asset graph"
      style={style}
      data-testid="graph-visualization"
    >
      <header className="graph-toolbar">
        <div className="graph-toolbar-group">
          <label htmlFor="graph-search">Search</label>
          <input
            id="graph-search"
            type="search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search by node name"
            aria-label="Search nodes by name"
            data-testid="graph-search-input"
          />
        </div>

        <div className="graph-toolbar-group">
          <label htmlFor="graph-type-filter">Node type</label>
          <select
            id="graph-type-filter"
            value={typeFilter}
            onChange={(event) => setTypeFilter(event.target.value)}
            aria-label="Filter nodes by type"
            data-testid="graph-type-filter"
          >
            <option value="all">All types</option>
            {knownTypes.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </div>

        <div className="graph-toolbar-group">
          <label htmlFor="graph-layout-select">Layout</label>
          <select
            id="graph-layout-select"
            value={layout}
            onChange={(event) => setLayout(event.target.value as LayoutKind)}
            aria-label="Select graph layout"
            data-testid="graph-layout-select"
          >
            {LAYOUT_KINDS.map((kind) => (
              <option key={kind} value={kind}>
                {kind}
              </option>
            ))}
          </select>
        </div>

        <div className="graph-toolbar-group graph-zoom-controls">
          <button
            type="button"
            onClick={zoomIn}
            aria-label="Zoom in"
            data-testid="graph-zoom-in"
          >
            +
          </button>
          <button
            type="button"
            onClick={zoomOut}
            aria-label="Zoom out"
            data-testid="graph-zoom-out"
          >
            −
          </button>
        </div>
      </header>

      <div className="graph-body">
        <div
          ref={containerRef}
          className="graph-canvas-container"
          tabIndex={0}
          role="application"
          aria-label="Graph canvas. Arrow keys pan, plus and minus zoom."
          onKeyDown={onKeyDown}
          data-testid="graph-canvas"
          style={{
            position: 'relative',
            width: '100%',
            height: '100%',
            minHeight: 400,
            outline: 'none',
            touchAction: 'none', // let sigma consume pinch/pan gestures
          }}
        >
          {showSkeleton && (
            <div
              className="graph-skeleton"
              role="status"
              aria-live="polite"
              data-testid="graph-skeleton"
            >
              Loading graph…
            </div>
          )}
          {loadState === 'error' && (
            <div
              className="graph-error"
              role="alert"
              data-testid="graph-error-banner"
            >
              {errorMessage || 'graph unavailable'}
            </div>
          )}
        </div>

        {selectedDetail && (
          <aside
            className="graph-details-panel"
            aria-label="Selected node details"
            data-testid="graph-details-panel"
          >
            <header>
              <h3>{nodeLabelOf(selectedDetail.node, selectedDetail.key)}</h3>
              <button
                type="button"
                onClick={() => setSelectedNodeId(null)}
                aria-label="Close details panel"
                data-testid="graph-details-close"
              >
                ×
              </button>
            </header>
            <dl>
              <dt>Type</dt>
              <dd data-testid="graph-details-type">{nodeTypeOf(selectedDetail.node)}</dd>
              {selectedDetail.node.severity && (
                <>
                  <dt>Severity</dt>
                  <dd>{selectedDetail.node.severity}</dd>
                </>
              )}
              {selectedDetail.node.on_critical_path && (
                <>
                  <dt>Critical path</dt>
                  <dd>yes</dd>
                </>
              )}
            </dl>
            <section>
              <h4>Properties</h4>
              {selectedDetail.node.metadata &&
              Object.keys(selectedDetail.node.metadata).length > 0 ? (
                <ul data-testid="graph-details-properties">
                  {Object.entries(selectedDetail.node.metadata).map(([k, v]) => (
                    <li key={k}>
                      <strong>{k}</strong>: {formatMetadataValue(v)}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="muted-copy">No properties recorded.</p>
              )}
            </section>
            <section>
              <h4>Edges ({selectedDetail.edges.length})</h4>
              {selectedDetail.edges.length > 0 ? (
                <ul data-testid="graph-details-edges">
                  {selectedDetail.edges.map((edge, i) => {
                    const ends = edgeEndpoints(edge)
                    if (!ends) return null
                    const other =
                      ends.source === selectedDetail.key ? ends.target : ends.source
                    const otherNode = nodesByKey.get(other)
                    const otherLabel = otherNode
                      ? nodeLabelOf(otherNode, other)
                      : other
                    return (
                      <li key={`${edge.edge_type ?? 'edge'}-${i}`}>
                        <span>{edge.edge_type ?? edge.label ?? 'related'}</span>
                        {' → '}
                        <span>{otherLabel}</span>
                      </li>
                    )
                  })}
                </ul>
              ) : (
                <p className="muted-copy">No edges.</p>
              )}
            </section>
          </aside>
        )}
      </div>

      <footer
        className="graph-legend"
        aria-label="Node type legend"
        data-testid="graph-legend"
      >
        {(activeTypes.length > 0 ? activeTypes : Object.keys(NODE_TYPE_COLORS)).map((type) => (
          <span key={type} className="graph-legend-entry">
            <span
              className="graph-legend-swatch"
              style={{
                display: 'inline-block',
                width: 12,
                height: 12,
                marginRight: 6,
                borderRadius: '50%',
                background: colorForNodeType(type),
                verticalAlign: 'middle',
              }}
              aria-hidden="true"
            />
            <span>{type}</span>
          </span>
        ))}
      </footer>
    </section>
  )
}

function formatMetadataValue(value: unknown): string {
  if (value == null) return '-'
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  try {
    return JSON.stringify(value)
  } catch {
    return String(value)
  }
}

function applyLayoutPositions(
  graph: GraphologyLike,
  keys: string[],
  edges: Array<{ source: string; target: string }>,
  layout: LayoutKind,
  nodesByKey: Map<string, GraphNode>,
): void {
  let positions: Record<string, Position>
  switch (layout) {
    case 'circular':
      positions = circularLayout(keys)
      break
    case 'hierarchical':
      positions = hierarchicalLayout(
        keys.map((key) => ({
          key,
          type: nodesByKey.get(key) ? nodeTypeOf(nodesByKey.get(key) as GraphNode) : 'UNKNOWN',
        })),
      )
      break
    case 'force':
    default:
      positions = forceLayout(keys, edges)
      break
  }
  for (const key of keys) {
    const pos = positions[key] ?? { x: 0, y: 0 }
    graph.setNodeAttribute(key, 'x', pos.x)
    graph.setNodeAttribute(key, 'y', pos.y)
  }
}

export default GraphVisualization
