import type {
  GraphEdge,
  GraphNode,
  GraphologyFactory,
  LayoutKind,
  Position,
  SigmaFactory,
  SigmaLoader,
} from './GraphVisualization'

export const LAYOUT_KINDS: readonly LayoutKind[] = ['circular', 'force', 'hierarchical'] as const

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

/** Evenly distribute nodes on a unit circle. Deterministic for a given order. */
export function circularLayout(keys: string[]): Record<string, Position> {
  const positions: Record<string, Position> = {}
  const count = Math.max(1, keys.length)
  keys.forEach((key, index) => {
    const theta = (2 * Math.PI * index) / count
    positions[key] = { x: Math.cos(theta), y: Math.sin(theta) }
  })
  return positions
}

/** Deterministic, lightweight Fruchterman-Reingold layout. */
export function forceLayout(
  keys: string[],
  edges: Array<{ source: string; target: string }>,
  iterations = 60,
): Record<string, Position> {
  const nodeCount = Math.max(1, keys.length)
  const optimalDistance = Math.sqrt(1 / nodeCount)
  const positions: Record<string, Position> = {}

  keys.forEach((key, index) => {
    const seed = hashSeed(key) + index
    positions[key] = {
      x: Math.cos(seed) * 0.5,
      y: Math.sin(seed) * 0.5,
    }
  })

  let temperature = 0.1
  const cooling = temperature / (iterations + 1)

  for (let iteration = 0; iteration < iterations; iteration += 1) {
    const displacements: Record<string, Position> = {}
    keys.forEach((key) => {
      displacements[key] = { x: 0, y: 0 }
    })

    for (let leftIndex = 0; leftIndex < keys.length; leftIndex += 1) {
      for (let rightIndex = leftIndex + 1; rightIndex < keys.length; rightIndex += 1) {
        const left = keys[leftIndex]
        const right = keys[rightIndex]
        const leftPosition = positions[left]
        const rightPosition = positions[right]
        const deltaX = leftPosition.x - rightPosition.x
        const deltaY = leftPosition.y - rightPosition.y
        const distance = Math.max(1e-4, Math.sqrt(deltaX * deltaX + deltaY * deltaY))
        const force = (optimalDistance * optimalDistance) / distance
        const forceX = (deltaX / distance) * force
        const forceY = (deltaY / distance) * force
        displacements[left].x += forceX
        displacements[left].y += forceY
        displacements[right].x -= forceX
        displacements[right].y -= forceY
      }
    }

    for (const edge of edges) {
      const sourcePosition = positions[edge.source]
      const targetPosition = positions[edge.target]
      if (!sourcePosition || !targetPosition) continue
      const deltaX = sourcePosition.x - targetPosition.x
      const deltaY = sourcePosition.y - targetPosition.y
      const distance = Math.max(1e-4, Math.sqrt(deltaX * deltaX + deltaY * deltaY))
      const force = (distance * distance) / optimalDistance
      const forceX = (deltaX / distance) * force
      const forceY = (deltaY / distance) * force
      displacements[edge.source].x -= forceX
      displacements[edge.source].y -= forceY
      displacements[edge.target].x += forceX
      displacements[edge.target].y += forceY
    }

    for (const key of keys) {
      const displacement = displacements[key]
      const magnitude = Math.max(
        1e-4,
        Math.sqrt(displacement.x * displacement.x + displacement.y * displacement.y),
      )
      const capped = Math.min(magnitude, temperature)
      positions[key].x += (displacement.x / magnitude) * capped
      positions[key].y += (displacement.y / magnitude) * capped
    }
    temperature = Math.max(cooling, temperature - cooling)
  }
  return positions
}

function hashSeed(value: string): number {
  let hash = 5381
  for (let index = 0; index < value.length; index += 1) {
    hash = ((hash << 5) + hash + value.charCodeAt(index)) | 0
  }
  return (Math.abs(hash) % 1000) / 100
}

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

  const layers = [...byLayer.keys()].sort((left, right) => {
    const leftIndex = canonicalOrder.indexOf(left)
    const rightIndex = canonicalOrder.indexOf(right)
    if (leftIndex !== -1 && rightIndex !== -1) return leftIndex - rightIndex
    if (leftIndex !== -1) return -1
    if (rightIndex !== -1) return 1
    return left.localeCompare(right)
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
  const Graph = typeof graphologyGlobal === 'function' ? graphologyGlobal : graphologyGlobal?.Graph
  if (!Sigma || !Graph) {
    throw new Error('sigma or graphology UMD globals unavailable after script load')
  }
  return { Sigma, Graph }
}
