export function formatRelativeTime(iso: string, now: Date = new Date()): string {
  if (!iso) return 'unknown'
  const then = new Date(iso)
  const ms = then.getTime()
  if (Number.isNaN(ms)) return iso
  const diffSec = Math.round((now.getTime() - ms) / 1000)
  const abs = Math.abs(diffSec)
  const suffix = diffSec >= 0 ? 'ago' : 'from now'
  if (abs < 5) return 'just now'
  if (abs < 60) return `${abs}s ${suffix}`
  if (abs < 3600) return `${Math.round(abs / 60)}m ${suffix}`
  if (abs < 86_400) return `${Math.round(abs / 3600)}h ${suffix}`
  if (abs < 30 * 86_400) return `${Math.round(abs / 86_400)}d ${suffix}`
  return then.toISOString().slice(0, 10)
}

/** Keep the current page and its neighbors visible between the first and last pages. */
export function pageWindow(current: number, total: number): (number | 'gap')[] {
  if (total <= 1) return [1]
  const out: (number | 'gap')[] = []
  const push = (value: number | 'gap') => {
    const last = out[out.length - 1]
    if (value === 'gap' && last === 'gap') return
    out.push(value)
  }
  const wanted = new Set<number>([1, total, current, current - 1, current + 1])
  const sorted = Array.from(wanted)
    .filter((page) => page >= 1 && page <= total)
    .sort((left, right) => left - right)
  let previous = 0
  for (const page of sorted) {
    if (page - previous > 1) push('gap')
    push(page)
    previous = page
  }
  return out
}
