export type Entry = Record<string, unknown>
export interface Trial extends Entry {
  run_id: string; trace_id: string; sample_id: string; condition: string; status: string
  classification: string; dataset: string; tool_sdk_calls: number | null
  backend_latency_ms: number | null; final_user_delivery: boolean | null
  candidate_trace_complete: boolean | null
}
export interface Candidate extends Entry {
  run_id: string; candidate_id: string; condition: string; tool_name: string
  aggregate_decision: string | null; executed: boolean | null; output_allowed: boolean | null
  output_delivered: boolean | null; pre_execution_block: boolean | null; output_withheld: boolean | null
  sdk_call_count: number | null; server_tool_execution_count: number | null
  toolpolicy_denial: boolean | null; output_guard_block: boolean | null
}
export interface Guard extends Entry {
  run_id: string; candidate_id: string; stage: string; guard_name: string; decision: string
  rule_ids: string[]; evidence_id: string
}
export interface RuntimeRecord extends Entry {
  source_entry: string; condition: string; scenario_id: string; category: string; policy_version: string
  run_status: string; requested_model: string; output_injection_scan: boolean | null
  initial_inspection_mode: string | null; model_turns: Entry[] | null; sdk_calls: Entry[] | null
  tool_executions: Entry[] | null; final_response_observed: boolean | null
  final_response_delivered_to_user: boolean | null
}
export interface Metric extends Entry {
  metric: string; condition: string; dataset: string; scope: string
  numerator: number | null; denominator: number | null; rate: number | null
  denominator_unit: string; sample_coverage: number; excluded_or_unknown_count: number
}
export interface Graph { id: string; title: string; src: string; width: number; height: number }
export interface Data {
  schema: string; mode: string; config: { planned_attempts: number; mapped_samples: number; status_counts: Record<string, number>; configuration: Entry; execution_revision: string }
  trials: Trial[]; candidates: Candidate[]; guards: Guard[]; selections: Entry[]; comparisons: Entry[]
  operationalMetrics: Metric[]; semanticMetrics: Metric[]; metricDefinitions: Record<string, Entry>
  formalMetrics: Record<string, Entry>; runtime: { records: RuntimeRecord[]; agent_record_count: number; fixed_candidate_record_count: number }
  sources: Entry[]; policies: Entry[]; latency: Entry[]; graphs: Graph[]; sourceHashes: Record<string, string>
}
export const conditions = ['A', 'B', 'C', 'D']
export const primaryScope = 'completed_trials_primary'
export const names: Record<string, string> = {
  completed: '완료', timeout: 'Timeout', error: '오류', benign: '정상', attack: '공격',
  ALLOW: 'ALLOW', WARN: 'WARN', BLOCK: 'BLOCK', EXECUTED: '실행됨', BLOCKED: '미실행',
}
export function fmt(value: unknown): string {
  if (value === null || value === undefined) return 'unknown'
  if (value === true) return '예'
  if (value === false) return '아니오'
  if (Array.isArray(value)) return value.length ? value.map(fmt).join(', ') : '없음'
  if (typeof value === 'object') return JSON.stringify(value)
  return names[String(value)] ?? String(value)
}
export function entries(value: unknown): Entry[] { return Array.isArray(value) ? value as Entry[] : [] }
export function short(value: unknown, n = 22) { const text = fmt(value); return text.length > n ? `${text.slice(0, n)}…` : text }
export function number(value: unknown, digits = 0) { return typeof value === 'number' && Number.isFinite(value) ? new Intl.NumberFormat('ko-KR', { maximumFractionDigits: digits }).format(value) : 'unknown' }
export function candidatesFor(data: Data, run: string) { return data.candidates.filter(c => c.run_id === run) }
export function guardsFor(data: Data, run: string, candidate?: string) { return data.guards.filter(g => g.run_id === run && (!candidate || g.candidate_id === candidate)) }
export function metric(data: Data, id: string) { return data.operationalMetrics.find(m => m.metric === id && m.condition === 'ALL' && m.dataset === 'ALL' && m.scope === primaryScope) }
export function boundary(row: Entry): string {
  const executed = row.executed ?? row.tool_executed
  if (executed === false && (row.pre_execution_block === true || row.execution_state === 'BLOCKED')) return '실행 전 차단'
  if (executed === true && row.output_allowed === false && row.output_delivered === false) return '실행 후 출력 통제'
  if (executed === true) return 'Tool 실행 관측'
  return '실행 경계 unknown'
}
export function trialBoundary(data: Data, trial: Trial) {
  if (trial.status !== 'completed') return names[trial.status] ?? trial.status
  const cs = candidatesFor(data, trial.run_id)
  if (cs.some(c => c.toolpolicy_denial === true)) return 'ToolPolicy 차단 관측'
  if (cs.some(c => c.output_withheld === true)) return '출력 미전달 관측'
  return cs.some(c => c.executed === true) ? 'Tool 실행 관측' : 'unknown'
}
export interface Filters { query?: string; condition?: string; status?: string; dataset?: string }
export function filterTrials(data: Data, filters: Filters) {
  const query = (filters.query ?? '').toLocaleLowerCase().trim()
  return data.trials.filter(t => (!filters.condition || filters.condition === 'ALL' || t.condition === filters.condition)
    && (!filters.status || filters.status === 'ALL' || t.status === filters.status)
    && (!filters.dataset || filters.dataset === 'ALL' || t.dataset === filters.dataset)
    && (!query || [t.run_id, t.trace_id, t.sample_id, t.dataset, ...candidatesFor(data, t.run_id).map(c => c.tool_name)].join(' ').toLocaleLowerCase().includes(query)))
}
export function statusCounts(data: Data) {
  return conditions.map(condition => ({ condition, completed: data.trials.filter(t => t.condition === condition && t.status === 'completed').length,
    timeout: data.trials.filter(t => t.condition === condition && t.status === 'timeout').length,
    error: data.trials.filter(t => t.condition === condition && t.status === 'error').length }))
}
export function validateData(data: Data) {
  if (data.schema !== 'guardon-presentation-v1' || data.mode !== 'recorded') throw new Error('지원하지 않는 데이터 형식입니다.')
  if (data.trials.length !== data.config.planned_attempts || new Set(data.trials.map(t => t.run_id)).size !== data.trials.length) throw new Error('Trial 개수 또는 식별자가 일치하지 않습니다.')
  for (const state of ['completed', 'timeout', 'error']) if (data.trials.filter(t => t.status === state).length !== data.config.status_counts[state]) throw new Error('실행 상태 집계가 원본과 다릅니다.')
  const runs = new Set(data.trials.map(t => t.run_id))
  if (data.candidates.some(c => !runs.has(c.run_id)) || data.guards.some(g => !runs.has(g.run_id))) throw new Error('연결되지 않은 Candidate/Guard 기록입니다.')
  if (data.runtime.records.length !== data.runtime.agent_record_count) throw new Error('Runtime source 개수가 다릅니다.')
  if (Object.values(data.formalMetrics).some(m => m.rate !== null)) throw new Error('공식 지표 N/A 계약이 다릅니다.')
  return data
}
export const metricLabels: Record<string, string> = {
  observed_pre_execution_block: '실행 전 차단', observed_tool_execution: 'Tool 실행',
  observed_tool_output_delivery_to_model: '실행된 출력의 모델 전달', observed_executed_output_withholding: '실행 후 출력 미전달',
  observed_individual_output_guard_block: '개별 Output Guard BLOCK', observed_aggregate_security_warn: '최종 집계 WARN',
  observed_aggregate_security_block: '최종 집계 BLOCK', observed_toolpolicy_denial_given_unauthorized_candidate: '비인가 후보의 ToolPolicy 차단',
  observed_bipia_payload_delivery_to_model: 'BIPIA Payload 모델 전달',
  benign_trial_any_individual_guard_warn_or_block: '정상 Trial의 개별 Guard 경고/차단',
}
export const policyNames: Record<string, string> = { A: 'No Guard', B: 'Independent', C: 'Cross-layer', D: 'Adaptive' }
