import { describe, expect, it } from 'vitest'
import archive from '../public/data/guardon.json'
import { type Data, validateData, filterTrials, statusCounts, boundary, fmt, candidatesFor } from './data'
import { resolveDetail } from './App'

const data = archive as unknown as Data

describe('validated recorded cohort', () => {
  it('keeps 48 attempts and 29 Runtime records separate, formal metrics N/A', () => {
    expect(validateData(data)).toBe(data)
    expect(data.trials).toHaveLength(48)
    expect(data.runtime.records).toHaveLength(29)
    expect(statusCounts(data).reduce((sum, r) => sum + r.completed, 0)).toBe(41)
    expect(statusCounts(data).reduce((sum, r) => sum + r.timeout, 0)).toBe(5)
    expect(statusCounts(data).reduce((sum, r) => sum + r.error, 0)).toBe(2)
    expect(Object.values(data.formalMetrics).every(m => m.rate === null)).toBe(true)
  })
  it('rejects a duplicate identity', () => {
    const broken = structuredClone(data)
    broken.trials[1].run_id = broken.trials[0].run_id
    expect(() => validateData(broken)).toThrow(/식별자/)
  })
  it('rejects forged completion counts', () => {
    const broken = structuredClone(data)
    broken.trials[0].status = 'error'
    expect(() => validateData(broken)).toThrow(/집계/)
  })
  it('rejects fabricated zero percent for a formal N/A metric', () => {
    const broken = structuredClone(data)
    Object.values(broken.formalMetrics)[0].rate = 0
    expect(() => validateData(broken)).toThrow(/N\/A/)
  })
})

describe('search, filters and investigation', () => {
  it('finds an exact run without changing the underlying cohort', () => {
    expect(filterTrials(data, { query: data.trials[0].run_id })).toEqual([data.trials[0]])
    expect(data.trials).toHaveLength(48)
  })
  it('filters observed completed C trials', () => {
    const result = filterTrials(data, { condition: 'C', status: 'completed' })
    expect(result).toHaveLength(10)
    expect(result.every(t => t.condition === 'C' && t.status === 'completed')).toBe(true)
  })
  it('searches actual selected Runtime tool names', () => {
    const result = filterTrials(data, { query: 'demo/send_email' })
    expect(result.length).toBeGreaterThan(0)
    expect(result.every(t => candidatesFor(data, t.run_id).some(c => c.tool_name === 'demo/send_email'))).toBe(true)
  })
  it('preserves empty search results', () => expect(filterTrials(data, { query: 'not-an-existing-run' })).toEqual([]))
  it('opens the selected condition and scope, not a different metric cohort', () => {
    const row = data.operationalMetrics.find(m => m.condition === 'D' && m.scope === 'all_saved_attempts_diagnostic' && m.dataset === 'ALL')!
    expect(row).toBeDefined()
    const detail = resolveDetail(data, `metric:${row.metric}|${row.scope}|${row.condition}|${row.dataset}`)
    expect(detail?.value).toBe(row)
  })
})

describe('unknown and actual execution boundaries', () => {
  it('keeps unknown distinct from zero', () => { expect(fmt(null)).toBe('unknown'); expect(fmt(0)).toBe('0') })
  it('does not infer a pre-block from an aggregate decision alone', () => expect(boundary({ aggregate_decision: 'BLOCK', executed: null })).toBe('실행 경계 unknown'))
  it('shows actual pre-tool BLOCK with zero SDK calls', () => {
    const row = data.candidates.find(c => c.pre_execution_block === true)!
    expect(row.sdk_call_count).toBe(0)
    expect(boundary(row)).toBe('실행 전 차단')
  })
  it('does not turn executed output withholding into an individual Output Guard BLOCK', () => {
    const row = data.candidates.find(c => c.output_withheld === true && c.output_guard_block === false)!
    expect(row.executed).toBe(true)
    expect(row.output_guard_block).toBe(false)
    expect(boundary(row)).toBe('실행 후 출력 통제')
  })
})
