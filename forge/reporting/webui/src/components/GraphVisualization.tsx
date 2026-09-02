import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type KeyboardEvent,
} from 'react'

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

export const LAYOUT_KINDS: readonly LayoutKind[] = ['circular', 'force', 'hierarchical'] as const

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

// ---------------------------------------------------------------------------
// Legend / colors
// ---------------------------------------------------------------------------

/**
 * Node-type -> color map. Keys are upper-cased for stable matching against
 * both `node_type` and `entity_type` values returned by the graph API.
 */
export const NODE_TYPE_COLORS: Record<string, string> = {
  HOST: '#4a9eff',
  SERVICE: '#10b981',
  EMAIL: '#ffb84a',
  CREDENTIAL: '#ffb84a',
  CLOUD: '#a855f7',
  VULN: '#ef4444',
  IMPACT: '#f43f5e',
  EXTERNAL: '#64748b',
  SOCIAL: '#ec4899',
  IDENTITY: '#8b5cf6',
  ASSET: '#0ea5e9',
  ORGANIZATION: '#f59e0b',
  UNKNOWN: '#94a3b8',
}

export const NODE_FALLBACK_COLOR = '#94a3b8'

export function colorForNodeType(nodeType: string | undefined): string {
  if (!nodeType) return NODE_FALLBACK_COLOR
  const key = nodeType.toUpperCase()
  return NODE_TYPE_COLORS[key] ?? NODE_FALLBACK_COLOR
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function nodeKey(node: GraphNode, index: number): string {
  const raw = node.node_id ?? node.id
  if (typeof raw === 'string' && raw.length > 0) return raw
  return `node-${index}`
}

export function edgeEndpoints(edge: GraphEdge): { source: string; target: string } | null {
  const source = edge.source_node_id ?? edge.source
  const target = edge.target_node_id ?? edge.target
  if (typeof source !== 'string' || typeof target !== 'string') return null
  if (source.length === 0 || target.length === 0) return null
  return { source, target }
}

export function nodeTypeOf(node: GraphNode): string {
  const raw = node.node_type ?? node.entity_type ?? 'UNKNOWN'
  return String(raw).toUpperCase()
}

export function nodeLabelOf(node: GraphNode, key: string): string {
  const raw = node.label
  if (typeof raw === 'string' && raw.length > 0) return raw
  return key
}

// ---------------------------------------------------------------------------
// Layouts
// ---------------------------------------------------------------------------

export type Position = { x: number; y: number }

/** Evenly distribute nodes on a unit circle. Deterministic for a given order. */
export function circularLayout(keys: string[]): Record<string, Position> {
  const positions: Record<string, Position> = {}
  const n = Math.max(1, keys.length)
  keys.forEach((key, i) => {
    const theta = (2 * Math.PI * i) / n
    positions[key] = { x: Math.cos(theta), y: Math.sin(theta) }
  })
  return positions
}

/**
 * Simple force-directed (Fruchterman-Reingold-lite). Deterministic seed
 * derived from node keys so tests are reproducible.
 */
export function forceLayout(
  keys: string[],
  edges: Array<{ source: string; target: string }>,
  iterations = 60,
): Record<string, Position> {
  const n = Math.max(1, keys.length)
  const area = 1
  const k = Math.sqrt(area / n)

  const positions: Record<string, Position> = {}
  keys.forEach((key, i) => {
    const seed = hashSeed(key) + i
    positions[key] = {
      x: Math.cos(seed) * 0.5,
      y: Math.sin(seed) * 0.5,
    }
  })

  let temperature = 0.1
  const cooling = temperature / (iterations + 1)

  for (let iter = 0; iter < iterations; iter += 1) {
    const displacements: Record<string, Position> = {}
    keys.forEach((key) => {
      displacements[key] = { x: 0, y: 0 }
    })

    // Repulsion.
    for (let i = 0; i < keys.length; i += 1) {
      for (let j = i + 1; j < keys.length; j += 1) {
        const a = keys[i]
        const b = keys[j]
        const pa = positions[a]
        const pb = positions[b]
        const dx = pa.x - pb.x
        const dy = pa.y - pb.y
        const dist = Math.max(1e-4, Math.sqrt(dx * dx + dy * dy))
        const force = (k * k) / dist
        const fx = (dx / dist) * force
        const fy = (dy / dist) * force
        displacements[a].x += fx
        displacements[a].y += fy
        displacements[b].x -= fx
        displacements[b].y -= fy
      }
    }

    // Attraction along edges.
    for (const edge of edges) {
      const pa = positions[edge.source]
      const pb = positions[edge.target]
      if (!pa || !pb) continue
      const dx = pa.x - pb.x
      const dy = pa.y - pb.y
      const dist = Math.max(1e-4, Math.sqrt(dx * dx + dy * dy))
      const force = (dist * dist) / k
      const fx = (dx / dist) * force
      const fy = (dy / dist) * force
      displacements[edge.source].x -= fx
      displacements[edge.source].y -= fy
      displacements[edge.target].x += fx
      displacements[edge.target].y += fy
    }

    // Apply, capped by temperature.
    for (const key of keys) {
      const disp = displacements[key]
      const mag = Math.max(1e-4, Math.sqrt(disp.x * disp.x + disp.y * disp.y))
      const capped = Math.min(mag, temperature)
      positions[key].x += (disp.x / mag) * capped
      positions[key].y += (disp.y / mag) * capped
    }
    temperature = Math.max(cooling, temperature - cooling)
  }
  return positions
}

/** djb2-lite hash producing a bounded numeric seed. */
function hashSeed(value: string): number {
  let hash = 5381
  for (let i = 0; i < value.length; i += 1) {
    hash = ((hash << 5) + hash + value.charCodeAt(i)) | 0
  }
  return (Math.abs(hash) % 1000) / 100
}

/**
 * Hierarchical layout: layer nodes by node_type (or explicit `layer` metadata).
 * Layer order picks canonical categories first, then unknowns alphabetically.
 */
export function hierarchicalLayout(
  entries: Array<{ key: string; type: string }>,
): Record<string, Position> {
  const canonicalOrder = [
    'EXTERNAL',
    'IDENTITY',
    'CREDENTIAL',
    'EMAIL',
    'SOCIAL',
    'HOST',
    'SERVICE',
    'ASSET',
    'CLOUD',
    'VULN',
    'IMPACT',
    'ORGANIZATION',
    'UNKNOWN',
  ]
  const byLayer = new Map<string, string[]>()
  for (const entry of entries) {
    const layer = entry.type || 'UNKNOWN'
    const bucket = byLayer.get(layer) ?? []
    bucket.push(entry.key)
    byLayer.set(layer, bucket)
  }

  const layers = [...byLayer.keys()].sort((a, b) => {
    const ai = canonicalOrder.indexOf(a)
    const bi = canonicalOrder.indexOf(b)
    if (ai !== -1 && bi !== -1) return ai - bi
    if (ai !== -1) return -1
    if (bi !== -1) return 1
    return a.localeCompare(b)
  })

  const positions: Record<string, Position> = {}
  const layerCount = Math.max(1, layers.length)
  layers.forEach((layer, layerIndex) => {
    const nodes = byLayer.get(layer) ?? []
    const y = layerCount === 1 ? 0 : 1 - (2 * layerIndex) / (layerCount - 1)
    const count = Math.max(1, nodes.length)
    nodes.forEach((key, nodeIndex) => {
      const x = count === 1 ? 0 : -1 + (2 * nodeIndex) / (count - 1)
      positions[key] = { x, y }
    })
  })
  return positions
}

// ---------------------------------------------------------------------------
// Default Sigma / graphology loader (UMD from vendored /static/ tree).
// ---------------------------------------------------------------------------

type SigmaWindow = typeof window & {
  Sigma?: SigmaFactory
  graphology?: GraphologyFactory | { Graph?: GraphologyFactory }
}

const DEFAULT_SIGMA_URLS = {
  graphology: '/static/graphology/graphology.umd.min.js',
  sigma: '/static/sigma/sigma.min.js',
}

async function injectScript(url: string, id: string): Promise<void> {
  if (typeof document === 'undefined') {
    throw new Error(`cannot inject ${url} outside a DOM environment`)
  }
  const existing = document.getElementById(id)
  if (existing) return
  await new Promise<void>((resolve, reject) => {
    const script = document.createElement('script')
    script.id = id
    script.src = url
    script.async = true
    script.onload = () => resolve()
    script.onerror = () => reject(new Error(`failed to load ${url}`))
    document.head.appendChild(script)
  })
}

export const defaultSigmaLoader: SigmaLoader = async () => {
  const win = window as SigmaWindow
  if (!win.graphology) {
    await injectScript(DEFAULT_SIGMA_URLS.graphology, 'forge-vendor-graphology')
  }
  if (!win.Sigma) {
    await injectScript(DEFAULT_SIGMA_URLS.sigma, 'forge-vendor-sigma')
  }
  const Sigma = win.Sigma
  const graphologyGlobal = win.graphology
  const Graph =
    typeof graphologyGlobal === 'function'
      ? graphologyGlobal
      : graphologyGlobal?.Graph
  if (!Sigma || !Graph) {
    throw new Error('sigma or graphology UMD globals unavailable after script load')
  }
  return { Sigma, Graph }
}

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

  const [graphData, setGraphData] = useState<GraphPayload | null>(initialGraph ?? null)
  const [loadState, setLoadState] = useState<LoadState>(initialGraph ? 'ok' : 'idle')
  const [errorMessage, setErrorMessage] = useState<string>('')
  const [layout, setLayout] = useState<LayoutKind>(initialLayout)
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
        // Trigger re-render so the mount effect below can build the sigma
        // instance now that factories are ready.
        setLoadState((prev) => (prev === 'error' ? prev : prev))
        // Force a state update; use functional setState to avoid stale closure.
        setLayout((prev) => prev)
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
    applyLayoutPositions(graph, keys, normalizedEdges, layout, nodesByKey)

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
  }, [graphData, layout, nodesByKey])

  // Rebuild on data/factory readiness.
  useEffect(() => {
    if (!graphData) return
    if (!factoriesRef.current) return
    rebuildGraph()
  }, [graphData, rebuildGraph])

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
