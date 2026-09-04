import type { QualityThreshold } from './QualityWidget'

const THRESHOLD_GOOD = 80
const THRESHOLD_WARN = 50

export function classifyScore(score: number): QualityThreshold {
  if (score >= THRESHOLD_GOOD) {
    return 'good'
  }
  if (score >= THRESHOLD_WARN) {
    return 'warn'
  }
  return 'bad'
}
