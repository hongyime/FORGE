import '@testing-library/jest-dom'

// Vitest 5 + Windows Node 26: jsdom environment causes worker startup to exceed
// the 20-second fork timeout. We use environment:'node' in vitest.config.ts so
// workers start in < 5 s, then manually initialise jsdom here (setup phase has
// no startup timeout).
import { JSDOM } from 'jsdom'

const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
  url: 'http://localhost/',
})

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const w = dom.window as any

// Expose DOM globals expected by @testing-library/react
const DOM_GLOBALS = [
  'window', 'document', 'navigator', 'location', 'history',
  'Node', 'Element', 'HTMLElement', 'HTMLDivElement', 'HTMLSpanElement',
  'HTMLButtonElement', 'HTMLInputElement', 'HTMLAnchorElement',
  'HTMLFormElement', 'HTMLLabelElement', 'HTMLSelectElement',
  'HTMLTextAreaElement', 'HTMLImageElement', 'HTMLScriptElement',
  'Text', 'Comment', 'DocumentFragment', 'Attr',
  'Event', 'CustomEvent', 'KeyboardEvent', 'MouseEvent', 'PointerEvent',
  'FocusEvent', 'InputEvent', 'ClipboardEvent', 'WheelEvent', 'DragEvent',
  'MutationObserver', 'DOMParser', 'XMLSerializer', 'Range',
  'SVGElement', 'SVGSVGElement', 'CSSStyleDeclaration',
]

for (const key of DOM_GLOBALS) {
  if (key in w && !(key in globalThis)) {
    try {
      Object.defineProperty(globalThis, key, {
        configurable: true,
        writable: true,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
        value: w[key],
      })
    } catch {
      /* skip non-configurable props */
    }
  }
}

// Always override these (may exist as Node.js built-ins but wrong shape)
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const g = globalThis as any
g.window = w
g.document = w.document
// eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
g.getComputedStyle = w.getComputedStyle.bind(w)
// eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
g.requestAnimationFrame = w.requestAnimationFrame?.bind(w) ?? ((cb: FrameRequestCallback) => setTimeout(cb, 0))
// eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
g.cancelAnimationFrame = w.cancelAnimationFrame?.bind(w) ?? clearTimeout

if (!('ResizeObserver' in globalThis)) {
  g.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
}

if (!('matchMedia' in globalThis)) {
  g.matchMedia = (q: string) => ({
    matches: false,
    media: q,
    onchange: null,
    addListener() {},
    removeListener() {},
    addEventListener() {},
    removeEventListener() {},
    dispatchEvent: () => false,
  })
}

// Node ≥21 ships native fetch. Wire it into the jsdom window so components
// accessing window.fetch (e.g. GraphVisualization default fetcher) don't
// crash. If native fetch is absent, provide a stub that never resolves.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const nativeFetch = (globalThis as any).fetch as typeof fetch | undefined
if (!w.fetch) {
  w.fetch = nativeFetch ?? ((_url: string) => new Promise<Response>(() => undefined))
}
if (!('fetch' in globalThis)) {
  g.fetch = w.fetch
}
