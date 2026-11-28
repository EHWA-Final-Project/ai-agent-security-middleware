import { BrandMark, ProjectCredit } from './Branding'
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { ChartBar, TreeStructure, Columns, Flask, Fingerprint, MagnifyingGlass, Database, GitBranch, ArrowUpRight, ArrowRight, CaretRight, X, Copy, DownloadSimple, Info, FileText, Check, List } from '@phosphor-icons/react'
import { type Data, type Entry, type Trial, type Candidate, type RuntimeRecord, type Metric, type Graph, conditions, primaryScope, fmt, short, number, entries, candidatesFor, guardsFor, metric, filterTrials, statusCounts, validateData, boundary, trialBoundary, metricLabels, policyNames } from './data'

const nav = [
  { id: 'overview', label: 'Overview', ko: '실험 현황', icon: ChartBar },
  { id: 'agent', label: 'Agent Execution', ko: '실행 Trace', icon: TreeStructure },
  { id: 'comparison', label: 'A/B/C/D Comparison', ko: '조건별 비교', icon: Columns },
  { id: 'benchmark', label: 'External Benchmark', ko: '외부 평가', icon: Flask },
  { id: 'evidence', label: 'Evidence Explorer', ko: '근거 조사', icon: Fingerprint },
]
type Update = (values: Record<string, string | null>, replace?: boolean) => void
type Inspect = (token: string) => void
type Detail = { kind: string; title: string; value: Entry; trial?: Trial; runtime?: RuntimeRecord; graph?: Graph }
const base = import.meta.env.BASE_URL

function Status({ value }: { value: unknown }) {
  const raw = typeof value === 'string' ? value : 'unknown'
  const tone = ['completed', 'ALLOW'].includes(raw) ? 'good' : ['BLOCK', 'error'].includes(raw) ? 'bad' : ['timeout', 'WARN'].includes(raw) ? 'warn' : 'neutral'
  return <span className={`status ${tone}`}><i aria-hidden="true" />{fmt(value)}</span>
}
function Empty({ children = '일치하는 기록이 없습니다. 검색어나 필터를 변경하세요.' }: { children?: ReactNode }) { return <div className="empty-state"><MagnifyingGlass size={24} aria-hidden="true" /><p>{children}</p></div> }
function Section({ title, note, action, children, className = '' }: { title: string; note?: string; action?: ReactNode; children: ReactNode; className?: string }) {
  return <section className={`section ${className}`}><header className="section-heading"><div><h2>{title}</h2>{note && <p>{note}</p>}</div>{action}</header>{children}</section>
}
function Select({ label, value, onChange, options }: { label: string; value: string; onChange: (v: string) => void; options: { value: string; label: string }[] }) {
  return <label className="select-control"><span>{label}</span><select aria-label={label} name={label} value={value} onChange={e => onChange(e.target.value)}>{options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}</select></label>
}
function Search({ value, onChange, onSearch, label = '기록 검색' }: { value: string; onChange: (v: string) => void; onSearch: () => void; label?: string }) {
  return <form className="search" role="search" onSubmit={e => { e.preventDefault(); onSearch() }}><MagnifyingGlass size={17} aria-hidden="true" /><label className="sr-only" htmlFor="global-search">{label}</label><input id="global-search" name="query" value={value} onChange={e => onChange(e.target.value)} placeholder="Trial, Run, Tool 검색…" title="Enter로 전체 Evidence 조사" autoComplete="off" spellCheck={false} />{value && <button type="button" aria-label="검색 지우기" onClick={() => onChange('')}><X size={14} aria-hidden="true" /></button>}</form>
}
function Facts({ items }: { items: [string, unknown][] }) { return <dl className="facts">{items.map(([label, value]) => <div key={label}><dt>{label}</dt><dd title={typeof value === 'string' ? value : undefined}>{fmt(value)}</dd></div>)}</dl> }
function Note({ children }: { children: ReactNode }) { return <p className="note"><Info size={15} aria-hidden="true" /><span>{children}</span></p> }
function Raw({ value, title = '원본 필드 확인' }: { value: unknown; title?: string }) { return <details className="raw-record"><summary><FileText size={15} aria-hidden="true" />{title}</summary><pre tabIndex={0}>{JSON.stringify(value, null, 2)}</pre></details> }

function OutcomeChart({ data }: { data: Data }) {
  const counts = statusCounts(data)
  return <div className="outcome-chart"><div className="chart-legend"><span><i className="legend-good" />완료</span><span><i className="legend-warn" />Timeout</span><span><i className="legend-bad" />오류</span><span className="push">각 조건 12시도</span></div>
    <svg viewBox="0 0 720 228" role="img" aria-label={`조건별 실제 실행 상태: ${counts.map(r => `${r.condition} 완료 ${r.completed} Timeout ${r.timeout} 오류 ${r.error}`).join(', ')}`}>
      {[0, 3, 6, 9, 12].map(n => <g key={n}><line x1={126 + n * 41} y1="16" x2={126 + n * 41} y2="200" className="grid-line" /><text x={126 + n * 41} y="220" textAnchor="middle" className="axis-text">{n}</text></g>)}
      {counts.map((r, i) => { const y = 28 + i * 45; return <g key={r.condition}><text x="12" y={y + 20} className="chart-condition">{r.condition}</text><text x="39" y={y + 20} className="chart-policy">{policyNames[r.condition]}</text><rect x="126" y={y} width={r.completed * 41} height="29" className="fill-good"><title>{r.condition} 완료 {r.completed}</title></rect><text x={126 + r.completed * 41 - 14} y={y + 20} className="bar-value" textAnchor="end">{r.completed}</text><rect x={126 + r.completed * 41} y={y} width={r.timeout * 41} height="29" className="fill-warn"><title>Timeout {r.timeout}</title></rect>{r.timeout > 0 && <text x={126 + (r.completed + r.timeout / 2) * 41} y={y + 20} textAnchor="middle" className="bar-dark">{r.timeout}</text>}<rect x={126 + (r.completed + r.timeout) * 41} y={y} width={r.error * 41} height="29" className="fill-bad"><title>오류 {r.error}</title></rect>{r.error > 0 && <text x={126 + (12 - r.error / 2) * 41} y={y + 20} textAnchor="middle" className="bar-value">{r.error}</text>}<text x="651" y={y + 20} className="chart-total">12</text></g> })}
    </svg><div className="chart-foot"><span>완료는 과제 성공을 뜻하지 않습니다.</span><span>단위: 실행 시도</span></div></div>
}

function MetricRows({ data, inspect }: { data: Data; inspect: Inspect }) {
  return <div className="metric-rows">{['observed_pre_execution_block', 'observed_tool_execution', 'observed_tool_output_delivery_to_model', 'observed_executed_output_withholding'].map(id => { const m = metric(data, id); return <button key={id} className="metric-row" onClick={() => inspect(`metric:${id}`)}><span>{metricLabels[id]}</span><strong>{m ? `${m.numerator ?? 'unknown'} / ${m.denominator ?? 'unknown'}` : 'unknown'}</strong><CaretRight size={15} aria-hidden="true" /></button>})}<p className="small muted">완료 Trial의 Candidate 관측 · 공식 방어 성공률이 아닙니다.</p></div>
}

function TrialTable({ data, trials, inspect, selected, select, compact = false }: { data: Data; trials: Trial[]; inspect: Inspect; selected?: string; select?: (id: string) => void; compact?: boolean }) {
  const [page, setPage] = useState(0)
  const limit = compact ? 6 : 10
  useEffect(() => setPage(0), [trials.length])
  const safePage = Math.min(page, Math.max(0, Math.ceil(trials.length / limit) - 1))
  const displayed = trials.slice(safePage * limit, (safePage + 1) * limit)
  if (!trials.length) return <Empty />
  return <><div className="table-scroll"><table className="data-table"><thead><tr><th>조건</th><th>표본 / Run</th><th>상태</th><th>SDK 호출</th>{!compact && <th>관측 경계</th>}<th><span className="sr-only">상세 조사</span></th></tr></thead><tbody>{displayed.map(t => <tr key={t.run_id} className={selected === t.run_id ? 'selected-row' : ''}><td><span className={`condition cond-${t.condition}`}>{t.condition}</span></td><td><button className="row-link" onClick={() => select ? select(t.run_id) : inspect(t.run_id)}>{t.sample_id}</button><span className="row-sub mono" title={t.run_id}>{short(t.run_id, compact ? 27 : 34)} <span className="dataset-tag">{t.dataset.toUpperCase()} · {fmt(t.classification)}</span></span></td><td><Status value={t.status} /></td><td className="numeric">{fmt(t.tool_sdk_calls)}</td>{!compact && <td className="small">{trialBoundary(data, t)}</td>}<td><button className="icon-button" aria-label={`${t.run_id} Evidence 열기`} onClick={() => inspect(t.run_id)}><ArrowUpRight size={17} aria-hidden="true" /></button></td></tr>)}</tbody></table></div>{trials.length > limit && <div className="pagination"><span>{trials.length}개 중 {safePage * limit + 1}–{Math.min((safePage + 1) * limit, trials.length)}</span><div><button disabled={safePage === 0} onClick={() => setPage(safePage - 1)}>이전</button><button disabled={(safePage + 1) * limit >= trials.length} onClick={() => setPage(safePage + 1)}>다음</button></div></div>}</>
}

function Overview({ data, params, inspect, go }: { data: Data; params: URLSearchParams; inspect: Inspect; go: (view: string) => void }) {
  const c = data.config
  const trials = filterTrials(data, { query: params.get('q') ?? '' })
  const records = trials.filter(t => t.sample_id === 'bipia-table-pair-001:attack' || (t.condition === 'C' && t.sample_id === 'bipia-table-pair-001:benign'))
  return <><div className="page-heading"><div><p className="eyebrow">RESEARCH OVERVIEW</p><h1>실험 현황</h1><p>Agent의 선택과 실제 실행, 출력 전달을 구분해 확인합니다.</p></div><button className="button" onClick={() => inspect('sources')}><Database size={16} aria-hidden="true" />출처 및 평가 범위</button></div>
    <div className="kpi-strip">{[['외부 표본', c.mapped_samples, '정상 6 · 공격 6'], ['실행 시도', c.planned_attempts, 'A/B/C/D · 단일 반복'], ['완료', c.status_counts.completed, '실행 완료 ≠ 과제 성공'], ['Timeout', c.status_counts.timeout, '부분 실행 기록 보존'], ['Runtime 오류', c.status_counts.error, '차단 성공에 미포함']].map(([label, value, sub]) => <div key={label}><span>{label}</span><strong>{value}</strong><small>{sub}</small></div>)}</div>
    <div className="overview-grid"><Section title="조건별 실행 결과" note="Qwen3:8b · MCP stdio · 저장된 실제 외부 평가" action={<button className="text-button" onClick={() => go('benchmark')}>평가 보기 <ArrowRight size={14} aria-hidden="true" /></button>}><OutcomeChart data={data} /></Section><Section title="실행·전달 경계" note="관측 분자 / 적격 분모"><MetricRows data={data} inspect={inspect} /></Section></div>
    <div className="overview-grid lower"><Section title="주요 실행 기록" note="동일 공격 표본의 조건별 실행과 C의 정상 실행" action={<button className="text-button" onClick={() => go('evidence')}>전체 48시도 <ArrowRight size={14} aria-hidden="true" /></button>}><TrialTable data={data} trials={records} inspect={inspect} compact /><Note>ToolPolicy 차단과 Injection 탐지, 모델 전달과 사용자 전달은 별도입니다.</Note></Section><Section title="정책 구성" note="현재 코드의 정책 정의 · 과거 Trial 설정과 구분"><div className="policy-list">{conditions.map(condition => <div key={condition}><span className={`condition cond-${condition}`}>{condition}</span><div><strong>{policyNames[condition]}</strong><p>{({ A: 'Guard 비활성 기준선', B: '각 Guard의 독립 검사', C: '계층 간 위험 신호 연결', D: 'FAST → 위험 신호 시 STANDARD' })[condition]}</p></div></div>)}</div></Section></div>
    <div className="research-limit"><span className="limit-tag">공식 지표 N/A</span><p>ASR · TSR · FPR을 확정할 의미 판정·최종 사용자 전달·완전한 전송 감사 근거가 부족합니다.</p><button className="text-button" onClick={() => inspect('sources')}>한계 확인 <ArrowUpRight size={14} aria-hidden="true" /></button></div>
  </>
}

function Trace({ data, trial, runtime, inspect, candidateIndex, setCandidateIndex }: { data: Data; trial?: Trial; runtime?: RuntimeRecord; inspect: Inspect; candidateIndex: number; setCandidateIndex: (n: number) => void }) {
  const cs: Entry[] = runtime ? entries(runtime.tool_executions) : trial ? candidatesFor(data, trial.run_id) : []
  const index = Math.min(candidateIndex, Math.max(cs.length - 1, 0))
  const row = cs[index]
  if (!row) return <Empty>Runtime Candidate 기록이 없습니다. 모델 선택과 오류/Timeout 원본을 상세 패널에서 확인하세요.</Empty>
  const run = trial?.run_id ?? String(row.run_id ?? '')
  const gs = runtime ? [] : guardsFor(data, run, String(row.candidate_id))
  const executed = row.executed ?? row.tool_executed
  const decision = row.aggregate_decision ?? row.security_decision
  const server = runtime ? row.server_call_counts : row.server_tool_execution_count
  const pre = gs.filter(g => g.stage !== 'OUTPUT')
  const post = gs.filter(g => g.stage === 'OUTPUT')
  const selected = runtime ? entries(runtime.model_turns).filter(t => t.turn === row.model_turn) : data.selections.filter(s => s.run_id === run)
  const stageRows: { title: string; subtitle: string; value: unknown; detail: unknown }[] = [
    { title: '모델 Tool 선택', subtitle: `${fmt(row.tool_name)} · 모델 턴 ${fmt(row.model_turn)}`, value: selected.length ? '관측됨' : 'unknown', detail: selected },
    { title: '실행 전 Guard', subtitle: runtime ? '개별 Guard 결과는 공개 요약에 미포함' : pre.map(g => `${g.guard_name}: ${g.decision}`).join(' · ') || '개별 Guard 기록 없음', value: pre.length ? pre.map(g => g.decision).join(' / ') : null, detail: pre },
    { title: 'MCP SDK 호출', subtitle: 'SDK 진입과 실제 서버 실행을 구분', value: row.sdk_call_count, detail: runtime ? entries(runtime.sdk_calls).filter(s => s.candidate_id === row.candidate_id) : { sdk_call_count: row.sdk_call_count, mcp_call_id: null } },
    { title: '서버 Tool 실행', subtitle: `실행 여부 ${fmt(executed)} · ${fmt(row.execution_state ?? (executed === true ? 'EXECUTED' : null))}`, value: server, detail: { server, executed } },
    { title: 'Output 통제', subtitle: `출력 허용 ${fmt(row.output_allowed)} · 모델 전달 ${fmt(row.output_delivered)}`, value: post.length ? post.map(g => g.decision).join(' / ') : null, detail: post.length ? post : { output_guard_block: row.output_guard_block ?? null, output_allowed: row.output_allowed, output_delivered: row.output_delivered } },
    { title: '후속 모델 / 최종 응답', subtitle: `후속 모델 전달 ${fmt(row.output_delivered)} · 최종 사용자 전달 ${fmt(runtime?.final_response_delivered_to_user ?? trial?.final_user_delivery)}`, value: runtime?.final_response_observed ?? null, detail: { followup_model_turn: row.followup_model_turn ?? null, final_response_observed: runtime?.final_response_observed ?? null, final_user_delivery: runtime?.final_response_delivered_to_user ?? trial?.final_user_delivery ?? null } },
  ]
  return <div className="trace-view"><div className="candidate-tabs" role="group" aria-label="Candidate 선택">{cs.map((c, i) => <button aria-pressed={i === index} key={String(c.candidate_id)} onClick={() => setCandidateIndex(i)}><span className="mono">{fmt(c.candidate_id)}</span><small>{fmt(c.tool_name).replace('demo/', '')}</small></button>)}</div>
    <div className="trace-summary"><div><span className="small muted">관측된 실행 경계</span><h3>{boundary(row)}</h3></div><div><span className="small muted">최종 집계 판정</span><Status value={decision} /></div></div>
    <ol className="timeline">{stageRows.map((stage, i) => <li key={stage.title}><span className={`step-marker ${i === 3 && executed === false ? 'blocked' : ''}`}>{String(i + 1).padStart(2, '0')}</span><div className="stage-body"><div className="stage-line"><strong>{stage.title}</strong><span className="stage-value">{typeof stage.value === 'object' && stage.value !== null ? Object.entries(stage.value).map(([k, v]) => `${k} ${fmt(v)}`).join(' · ') : fmt(stage.value)}</span></div><p>{stage.subtitle}</p>{i === 1 && pre.some(g => g.rule_ids.length) && <span className="rule-text">{pre.flatMap(g => g.rule_ids).join(' · ')}</span>}{i === 4 && executed === true && row.output_allowed === false && <span className="inline-warning">Tool은 실행되었으며 출력 허용은 별도로 통제되었습니다.</span>}</div></li>)}</ol>
    <div className="trace-bottom"><span className="mono muted" title={run}>{short(run, 34)}</span><button className="text-button" onClick={() => runtime ? inspect(`runtime:${data.runtime.records.indexOf(runtime)}`) : inspect(`candidate:${run}:${String(row.candidate_id)}`)}>Evidence 상세 <ArrowUpRight size={15} aria-hidden="true" /></button></div>
  </div>
}

function Filters({ params, update, dataset = false }: { params: URLSearchParams; update: Update; dataset?: boolean }) {
  return <div className="filters"><Select label="조건" value={params.get('condition') ?? 'ALL'} onChange={v => update({ condition: v, run: null })} options={[{ value: 'ALL', label: '전체 조건' }, ...conditions.map(c => ({ value: c, label: `${c} · ${policyNames[c]}` }))]} /><Select label="실행 상태" value={params.get('status') ?? 'ALL'} onChange={v => update({ status: v, run: null })} options={[{ value: 'ALL', label: '전체 상태' }, ...['completed', 'timeout', 'error'].map(s => ({ value: s, label: fmt(s) }))]} />{dataset && <Select label="데이터셋" value={params.get('dataset') ?? 'ALL'} onChange={v => update({ dataset: v, run: null })} options={[{ value: 'ALL', label: '전체 데이터셋' }, { value: 'bipia', label: 'BIPIA' }, { value: 'msb', label: 'MSB' }]} />}</div>
}

function Execution({ data, params, update, inspect, explorer = false }: { data: Data; params: URLSearchParams; update: Update; inspect: Inspect; explorer?: boolean }) {
  const runtimeMode = !explorer && (params.get('source') ?? 'runtime') === 'runtime'
  const query = (params.get('q') ?? '').toLowerCase()
  const [candidate, setCandidate] = useState(0)
  const trials = filterTrials(data, { query, condition: params.get('condition') ?? 'ALL', status: params.get('status') ?? 'ALL', dataset: params.get('dataset') ?? 'ALL' })
  const records = data.runtime.records.filter(r => (!params.get('condition') || params.get('condition') === 'ALL' || r.condition === params.get('condition')) && (!params.get('status') || params.get('status') === 'ALL' || r.run_status === params.get('status')) && (!query || [r.source_entry, r.scenario_id, r.policy_version, r.condition, ...entries(r.tool_executions).map(c => String(c.tool_name ?? ''))].join(' ').toLowerCase().includes(query)))
  const selectedRuntime = records.find(r => r.source_entry === params.get('run')) ?? records.find(r => r.condition === 'C' && r.category === 'abcd_multistep') ?? records[0]
  const selectedTrial = trials.find(t => t.run_id === params.get('run')) ?? trials.find(t => t.condition === 'B' && t.sample_id === 'bipia-table-pair-001:attack') ?? trials[0]
  useEffect(() => setCandidate(0), [params.get('run'), runtimeMode])
  return <><div className="page-heading"><div><p className="eyebrow">{explorer ? 'EVIDENCE EXPLORER' : 'AGENT EXECUTION'}</p><h1>{explorer ? 'Evidence 조사' : 'Agent 실행 Trace'}</h1><p>{explorer ? 'Trial → Candidate → Guard 근거를 따라 실행 경계를 조사합니다.' : '모델 선택부터 실제 MCP 실행과 후속 전달까지 관측한 기록입니다.'}</p></div><span className="source-count">{runtimeMode ? 'Runtime 인계 · 29 Agent 기록' : '외부 평가 · 48시도'}</span></div>
    {!explorer && <div className="source-tabs" role="group" aria-label="실행 자료 선택"><button aria-pressed={runtimeMode} onClick={() => update({ source: 'runtime', run: null })}>Runtime 인계 <span>29</span></button><button aria-pressed={!runtimeMode} onClick={() => update({ source: 'benchmark', run: null })}>외부 벤치마크 <span>48</span></button><p>두 source는 합산하지 않습니다.</p></div>}
    <Filters params={params} update={update} dataset={!runtimeMode} />
    <div className="investigation-layout"><section className="run-list"><header><h2>실행 목록</h2><span>{runtimeMode ? records.length : trials.length}개 기록</span></header>{runtimeMode ? records.length ? <div className="runtime-list">{records.map(r => <button key={r.source_entry} className={selectedRuntime === r ? 'active' : ''} onClick={() => update({ run: r.source_entry }, true)}><div><span className={`condition cond-${r.condition}`}>{r.condition}</span><Status value={r.run_status} /></div><strong>{r.category === 'abcd_multistep' ? '정상 다단계 실행' : r.category === 'abc_postblock' ? '실행 후 출력 통제' : r.category === 'abc_normal_preblock' ? '정상 / 비인가 Tool' : r.category}</strong><span className="small muted mono">{r.scenario_id}</span><span className="small muted">{entries(r.tool_executions).length} Candidate · {fmt(r.requested_model)}</span></button>)}</div> : <Empty /> : <TrialTable data={data} trials={trials} inspect={inspect} selected={selectedTrial?.run_id} select={id => update({ run: id }, true)} compact />}</section>
    <section className="trace-section"><header className="trace-title"><div><p className="eyebrow">SELECTED TRACE</p><h2>{runtimeMode ? selectedRuntime?.scenario_id ?? '선택 기록 없음' : selectedTrial?.sample_id ?? '선택 기록 없음'}</h2></div><Status value={runtimeMode ? selectedRuntime?.run_status : selectedTrial?.status} /></header>{runtimeMode && selectedRuntime && <div className="policy-context"><span className="mono">{selectedRuntime.policy_version}</span><span>PI-T01 {selectedRuntime.output_injection_scan === true ? 'ON' : selectedRuntime.output_injection_scan === false ? 'OFF' : 'unknown'}</span><span>초기 검사 {fmt(selectedRuntime.initial_inspection_mode)}</span></div>}{!runtimeMode && selectedTrial && <div className="policy-context"><span className="mono">{short(selectedTrial.run_id, 36)}</span><span>{selectedTrial.dataset.toUpperCase()} · {fmt(selectedTrial.classification)}</span><span>정확한 과거 policy_version: unknown</span></div>}
      <Trace data={data} runtime={runtimeMode ? selectedRuntime : undefined} trial={runtimeMode ? undefined : selectedTrial} inspect={inspect} candidateIndex={candidate} setCandidateIndex={setCandidate} />
    </section></div>
    <Note>{runtimeMode ? '과거 Runtime 인계 기록입니다. 29건에는 Timeout 주입 검증이 포함되며, 고정 후보 실제 MCP 검증 16건은 별도입니다.' : 'Timeout·오류의 부분 관측을 차단 성공으로 해석하지 않습니다. 출력의 모델 전달과 최종 사용자 전달은 다릅니다.'}</Note>
  </>
}

function Comparison({ data, params, update, inspect }: { data: Data; params: URLSearchParams; update: Update; inspect: Inspect }) {
  const samples = [...new Set(data.trials.map(t => t.sample_id))].sort()
  const sample = samples.includes(params.get('sample') ?? '') ? params.get('sample')! : 'bipia-table-pair-001:attack'
  const trials = conditions.map(c => data.trials.find(t => t.sample_id === sample && t.condition === c)!)
  const match = data.comparisons.find(c => c.sample_id === sample)
  const rows: { label: string; value: (t: Trial) => ReactNode }[] = [
    { label: '실행 상태', value: t => <Status value={t.status} /> },
    { label: '모델 Tool 선택 기록', value: t => fmt(t.recorded_selected_calls) },
    { label: 'SDK tools/call', value: t => fmt(t.tool_sdk_calls) },
    { label: 'Candidate 판정 흐름', value: t => candidatesFor(data, t.run_id).map(c => <span className="matrix-decision" key={c.candidate_id}><Status value={c.aggregate_decision} /></span>) },
    { label: 'ToolPolicy 차단', value: t => { const cs = candidatesFor(data, t.run_id); return cs.some(c => c.toolpolicy_denial === true) ? '관측됨' : t.candidate_trace_complete === true && cs.every(c => c.toolpolicy_denial === false) ? '미관측' : 'unknown' } },
    { label: '모델 대상 출력 전달', value: t => candidatesFor(data, t.run_id).map(c => <span className="matrix-candidate" key={c.candidate_id}>{c.candidate_id}: {fmt(c.output_delivered)}</span>) },
    { label: '최종 사용자 전달', value: t => fmt(t.final_user_delivery) },
    { label: '정확한 과거 policy_version', value: () => <span className="muted">unknown</span> },
  ]
  return <><div className="page-heading"><div><p className="eyebrow">MATCHED SAMPLE COMPARISON</p><h1>A/B/C/D 조건 비교</h1><p>같은 표본의 실제 관측을 나란히 비교합니다.</p></div><Select label="표본" value={sample} onChange={v => update({ sample: v })} options={samples.map(s => ({ value: s, label: s }))} /></div>
    <div className="sample-context"><span className="dataset-tag">{trials[0].dataset.toUpperCase()}</span><Status value={trials[0].classification} /><span>4조건 모두 완료: <strong>{fmt(match?.all_four_completed)}</strong></span><span>PI-T01: ON (실험 설정)</span></div>
    <div className="table-scroll matrix-scroll"><table className="comparison-matrix"><thead><tr><th>관측 항목</th>{trials.map(t => <th key={t.condition}><span className={`condition cond-${t.condition}`}>{t.condition}</span><strong>{policyNames[t.condition]}</strong><small>{t.condition === 'D' ? 'Adaptive inspection' : t.condition === 'C' ? 'Linked guards' : t.condition === 'B' ? 'Independent guards' : 'Guards disabled'}</small></th>)}</tr></thead><tbody>{rows.map(row => <tr key={row.label}><th scope="row">{row.label}</th>{trials.map(t => <td key={t.condition}>{row.value(t)}</td>)}</tr>)}<tr><th scope="row">실행 근거</th>{trials.map(t => <td key={t.condition}><button className="text-button" onClick={() => inspect(t.run_id)}>Trace 조사 <ArrowUpRight size={14} aria-hidden="true" /></button></td>)}</tr></tbody></table></div>
    <div className="comparison-notes"><Section title="C와 Adaptive D의 정책 차이" note="정책 정의를 설명하는 구조입니다. 실제 Trial별 검사 모드는 공개 표에서 unknown입니다."><div className="adaptive-flow"><div><span className="condition cond-C">C</span><strong>STANDARD</strong><small>계층 간 위험 연결</small></div><ArrowRight aria-hidden="true" /><div><span className="condition cond-D">D</span><strong>FAST</strong><small>위험 신호 확인</small></div><ArrowRight aria-hidden="true" /><div><strong>STANDARD 승격</strong><small>동일 필수 Guard · ToolPolicy</small></div></div></Section><Section title="비교 시 유의점"><p className="body-copy">모델 선택과 완료 표본이 다를 수 있습니다. Timeout·오류를 공격 차단 성공으로 세지 않으며, 단일 반복의 결과로 C/D 우열이나 인과적 방어 효과를 주장하지 않습니다.</p><Raw value={match} title="비교 완전성 원본" /></Section></div>
  </>
}

function MetricTable({ data, metrics, inspect }: { data: Data; metrics: Metric[]; inspect: Inspect }) {
  if (!metrics.length) return <Empty />
  return <div className="table-scroll"><table className="data-table metrics-table"><thead><tr><th>관측 지표</th><th>분자 / 분모</th><th>단위</th><th>제외·미확인</th><th>정의</th></tr></thead><tbody>{metrics.map(m => <tr key={m.metric}><td><strong>{metricLabels[m.metric] ?? m.metric.replaceAll('_', ' ')}</strong><small className="row-sub mono">{m.metric}</small></td><td className="numeric">{fmt(m.numerator)} <span className="muted">/ {fmt(m.denominator)}</span></td><td>{m.denominator_unit}</td><td className="numeric">{m.excluded_or_unknown_count}</td><td><button className="text-button" onClick={() => inspect(`metric:${m.metric}|${m.scope}|${m.condition}|${m.dataset}`)} aria-label={`${m.metric} 분모와 제외 사유`}>근거 <ArrowUpRight size={14} aria-hidden="true" /></button></td></tr>)}</tbody></table><span className="sr-only">{Object.keys(data.metricDefinitions).length}개 지표 정의가 연결되어 있습니다.</span></div>
}

function Benchmark({ data, params, update, inspect }: { data: Data; params: URLSearchParams; update: Update; inspect: Inspect }) {
  const scope = params.get('scope') ?? primaryScope
  const condition = params.get('condition') ?? 'ALL'
  const [graphId, setGraphId] = useState('execution')
  const graph = data.graphs.find(g => g.id === graphId) ?? data.graphs[0]
  const metrics = data.operationalMetrics.filter(m => m.scope === scope && m.condition === condition && m.dataset === 'ALL')
  const semantics = data.semanticMetrics.filter(m => m.scope === scope && m.condition === condition && m.dataset === 'ALL')
  return <><div className="page-heading"><div><p className="eyebrow">EXTERNAL BENCHMARK</p><h1>외부 벤치마크 평가</h1><p>BIPIA·MSB의 일부 변환 표본에 대한 실제 실행 관측입니다.</p></div><button className="button" onClick={() => inspect('sources')}><Database size={16} aria-hidden="true" />출처·라이선스</button></div>
    <div className="dataset-strip"><div><strong>BIPIA <span>TableQA</span></strong><p>5쌍 · 질문·공격 보존 · MCP Tool 응답으로 변환</p></div><div><strong>MSB <span>MCP-D01</span></strong><p>1쌍 · Tool 설명 경계로 변환</p></div><div className="formal-strip"><strong>ASR / TSR / FPR <span>N/A</span></strong><p>의미 판정·최종 전달·감사 근거 부족</p></div></div>
    <div className="benchmark-grid"><Section title="실행 결과 분포" note="조건별 실제 12시도"><OutcomeChart data={data} /></Section><Section title="평가 범위"><Facts items={[["표본", '정상 6 · 공격 6'], ['실행', '12표본 × A/B/C/D · 단일 반복'], ['모델', 'Qwen3:8b · MCP stdio'], ['설정', 'PI-T01 ON · 확장 규칙 unknown'], ['완전 비교', `${data.comparisons.filter(c => c.all_four_completed === true).length} / ${data.comparisons.length} 표본`]]} /></Section></div>
    <Section title="실행·차단 관측 지표" note="분모와 제외 사유를 함께 확인하세요. 공식 ASR/TSR/FPR과 별도입니다." action={<div className="filters compact"><Select label="관측 범위" value={scope} onChange={v => update({ scope: v })} options={[{ value: primaryScope, label: '완료 Trial · 주요 관측' }, { value: 'all_saved_attempts_diagnostic', label: '전체 시도 · 부분 기록 포함' }]} /><Select label="조건" value={condition} onChange={v => update({ condition: v })} options={['ALL', ...conditions].map(c => ({ value: c, label: c === 'ALL' ? '전체 조건' : c }))} /></div>}><MetricTable data={data} metrics={metrics} inspect={inspect} /></Section>
    <Section title="원본 평가 그래프" note="공유된 실제 실험 PNG 5종 · 원본 바이트 보존" action={<button className="text-button" onClick={() => inspect(`graph:${graph.id}`)}>확대 보기 <ArrowUpRight size={15} aria-hidden="true" /></button>}><div className="graph-tabs" role="group" aria-label="원본 그래프 선택">{data.graphs.map(g => <button key={g.id} aria-pressed={g.id === graph.id} onClick={() => setGraphId(g.id)}>{g.title}</button>)}</div><figure className="original-graph"><img src={`${base}${graph.src}`} alt={graph.title} width={graph.width} height={graph.height} loading="lazy" /><figcaption>{graph.title} · 단위와 적격 코호트는 원본 그래프 및 지표 정의를 따릅니다.</figcaption></figure></Section>
    <Section title="Backend Latency" note="완료 Trial만 · LLM 추론 포함 · 단위 s"><div className="table-scroll"><table className="data-table"><thead><tr><th>조건</th><th>완료 / 시도</th><th>Mean (s)</th><th>P50 (s)</th><th>P95 (s)</th></tr></thead><tbody>{data.latency.map(r => <tr key={String(r.condition)}><td><span className={`condition cond-${r.condition}`}>{fmt(r.condition)}</span></td><td>{fmt(r.completed)} / {fmt(r.attempted)}</td>{['mean_s', 'p50_s', 'p95_s'].map(key => <td className="numeric" key={key}>{r[key] === null || r[key] === undefined || r[key] === '' ? 'unknown' : number(Number(r[key]), 2)}</td>)}</tr>)}</tbody></table></div><Note>조건별 완료 표본이 다릅니다. Security Core 단독 Latency(ms)나 정책 추가 비용으로 해석하지 않습니다.</Note></Section>
    <details className="semantic-disclosure"><summary>의미 기반 사후 분석과 공식 N/A 사유</summary><MetricTable data={data} metrics={semantics} inspect={inspect} /><Raw value={data.formalMetrics} title="공식 지표의 분자·분모·N/A 사유" /></details>
  </>
}

function ProtocolEvidence({ data, trial, runtime }: { data: Data; trial?: Trial; runtime?: RuntimeRecord }) {
  const selections = runtime ? entries(runtime.model_turns) : trial ? data.selections.filter(s => s.run_id === trial.run_id) : []
  const sdk = runtime ? entries(runtime.sdk_calls) : []
  return <><h3>{runtime ? '모델 턴 관측' : 'Trial의 모델 Tool 선택'}</h3>{selections.length ? <div className="table-scroll"><table className="data-table drawer-table"><thead><tr><th>턴</th><th>{runtime ? '선택 수' : 'Tool'}</th><th>{runtime ? '종료 이유' : 'Runtime 진입'}</th></tr></thead><tbody>{selections.map((s, i) => <tr key={i}><td>{fmt(s.turn ?? s.model_turn)}</td><td>{fmt(runtime ? s.tool_call_count : s.tool_name)}</td><td>{fmt(runtime ? s.finish_reason : s.entered_runtime)}</td></tr>)}</tbody></table></div> : <p className="small muted">선택 기록 unknown</p>}{runtime && <><h3>실제 SDK 호출 관측</h3>{sdk.length ? <div className="table-scroll"><table className="data-table drawer-table"><thead><tr><th>메서드</th><th>Candidate</th><th>SDK 진입</th></tr></thead><tbody>{sdk.map((s, i) => <tr key={i}><td className="mono">{fmt(s.method)}</td><td>{fmt(s.candidate_id)}</td><td>{fmt(s.invoked)}</td></tr>)}</tbody></table></div> : <p className="small muted">호출별 SDK 목록 unknown · Candidate의 명시적 호출 수와 구분합니다.</p>}<Raw value={runtime.sdk_calls} title="SDK 시각·Tool·미관측 mcp_call_id" /></>}<Note>모델 선택과 Runtime Candidate 연결은 기록된 범위에서만 해석합니다. SDK 호출은 서버 진입 증거와 별도입니다.</Note></>
}

function DetailPanel({ detail, data, close }: { detail: Detail | null; data: Data; close: () => void }) {
  const ref = useRef<HTMLDialogElement>(null)
  const [copied, setCopied] = useState('')
  useEffect(() => { if (detail && !ref.current?.open) ref.current?.showModal(); setCopied('') }, [detail])
  if (!detail) return null
  async function copy(value: string) { try { await navigator.clipboard.writeText(value); setCopied('복사했습니다.') } catch { setCopied('복사할 수 없습니다. 원본 필드에서 선택해 복사하세요.') } }
  const row = detail.value
  const candidateRows = detail.trial ? candidatesFor(data, detail.trial.run_id).filter(c => detail.kind !== 'candidate' || c.candidate_id === row.candidate_id) : detail.runtime ? entries(detail.runtime.tool_executions) : []
  return <dialog ref={ref} className={`detail-panel ${detail.graph ? 'graph-panel' : ''}`} aria-labelledby="detail-title" onClose={close} onClick={e => { if (e.target === e.currentTarget) ref.current?.close() }}><div className="drawer-shell"><header className="drawer-heading"><div><p className="eyebrow">READ-ONLY EVIDENCE</p><h2 id="detail-title">{detail.title}</h2></div><button className="icon-button" aria-label="상세 패널 닫기" onClick={() => ref.current?.close()}><X size={20} aria-hidden="true" /></button></header><div className="drawer-content">
    {detail.graph ? <img className="expanded-graph" src={`${base}${detail.graph.src}`} alt={detail.graph.title} width={detail.graph.width} height={detail.graph.height} /> : detail.kind === 'sources' ? <><div className="drawer-callout"><Database size={20} aria-hidden="true" /><div><strong>Recorded / Replay Mode</strong><p>새 모델 호출 없이 검증된 공개 기록만 조회합니다.</p></div></div><Facts items={[["외부 평가", '12표본 · 48시도'], ['Runtime 인계', '29 Agent 기록 · 별도 집계'], ['고정 후보 MCP', '16건 · Agent/Benchmark와 별도'], ['공식 ASR/TSR/FPR', 'N/A']]} /><h3>데이터 출처와 변환</h3>{data.sources.filter(s => String(s.classification) === 'attack').map(s => { const provenance = s.provenance as Entry; return <div className="source-record" key={String(s.sample_id)}><strong>{fmt(s.sample_id)}</strong><a href={String(provenance.source_url)} target="_blank" rel="noreferrer">원본 저장소 <ArrowUpRight size={13} aria-hidden="true" /></a><Facts items={[["revision", provenance.revision], ['라이선스', provenance.context_license ?? provenance.license_spdx], ['공격 라이선스', provenance.attack_license ?? provenance.license_spdx]]} /><Raw value={s} title="변환·매핑·hash" /></div>})}<Raw value={data.formalMetrics} title="공식 지표 N/A 사유" /><Raw value={data.sourceHashes} title="공개 입력 SHA-256" /></> : detail.kind === 'metric' ? <><p className="metric-id mono">{fmt(row.metric)}</p><Facts items={[["조건", row.condition], ["데이터셋", row.dataset], ["분자", row.numerator], ['분모', row.denominator], ['단위', row.denominator_unit], ['scope', row.scope], ['표본 범위', row.sample_coverage], ['제외·미확인', row.excluded_or_unknown_count]]} /><h3>분모와 해석</h3><Raw value={data.metricDefinitions[String(row.metric)] ?? null} title="지표 정의" /><Raw value={row.exclusion_reasons ?? null} title="제외 사유" /><Note>관측 기반 기술통계입니다. 공식 ASR/TSR/FPR 또는 인과적 방어 효과로 대체하지 않습니다.</Note></> : <><div className="drawer-status"><Status value={row.status ?? row.run_status ?? row.aggregate_decision} /><span>{fmt(row.condition)} 조건</span></div><Facts items={[["표본 / 시나리오", row.sample_id ?? row.scenario_id], ['run_id', row.run_id ?? row.trial_run_id], ['trace_id', row.trace_id ?? row.trial_trace_id], ['policy_version', row.policy_version ?? null], ['최종 사용자 전달', row.final_user_delivery ?? row.final_response_delivered_to_user ?? null]]} />{typeof (row.run_id ?? row.trial_run_id) === 'string' && <button className="button" onClick={() => copy(String(row.run_id ?? row.trial_run_id))}><Copy size={15} aria-hidden="true" />Run ID 복사</button>}<span role="status" className="copy-status">{copied}</span>
    {candidateRows.length > 0 && <><h3>Candidate 실행 경계</h3>{candidateRows.map(c => <div className="candidate-evidence" key={String(c.candidate_id)}><div><strong className="mono">{fmt(c.candidate_id)}</strong><Status value={c.aggregate_decision ?? c.security_decision} /></div><p>{fmt(c.tool_name)} · {boundary(c)}</p><Facts items={[["Runtime run_id", c.runtime_run_id ?? c.run_id], ['SDK 호출', c.sdk_call_count], ['서버 실행', c.server_tool_execution_count ?? c.server_call_counts], ['출력 허용', c.output_allowed], ['모델 전달', c.output_delivered]]} /><Raw value={c.evidence_ids ?? c.evidence_refs ?? null} title="Evidence ID" /></div>)}</>}
    {detail.trial && <><h3>개별 Guard 결과</h3>{guardsFor(data, detail.trial.run_id).map(g => <div className="guard-evidence" key={g.evidence_id}><div><span>{g.stage} · {g.guard_name}</span><Status value={g.decision} /></div><p className="mono small">{g.rule_ids.length ? g.rule_ids.join(' · ') : 'triggered_rules 없음'}</p><small className="mono muted">{g.evidence_id}</small></div>)}</>}
    {detail.kind === 'candidate' && <Facts items={[["ToolPolicy 차단", row.toolpolicy_denial], ['개별 Output Guard BLOCK', row.output_guard_block], ['위험도 원본', null]]} />}
    <ProtocolEvidence data={data} trial={detail.trial} runtime={detail.runtime} />
    <Note>공개 관측의 식별자 연결입니다. 비공개 SQLite 원본을 새로 감사한 결과와 구분합니다.</Note></>}
    {!detail.graph && <Raw value={row} title="모든 공개 원본 필드" />}
  </div></div></dialog>
}

export function resolveDetail(data: Data, token: string | null): Detail | null {
  if (!token) return null
  if (token === 'sources') return { kind: 'sources', title: '데이터 출처 및 평가 범위', value: { config: data.config, sourceHashes: data.sourceHashes } }
  if (token.startsWith('metric:')) { const [id, scope = primaryScope, condition = 'ALL', dataset = 'ALL'] = token.slice(7).split('|'); const m = [...data.operationalMetrics, ...data.semanticMetrics].find(m => m.metric === id && m.condition === condition && m.dataset === dataset && m.scope === scope); return m ? { kind: 'metric', title: metricLabels[id] ?? '지표 근거', value: m } : null }
  if (token.startsWith('graph:')) { const graph = data.graphs.find(g => g.id === token.slice(6)); return graph ? { kind: 'graph', title: graph.title, value: { ...graph }, graph } : null }
  if (token.startsWith('runtime:')) { const runtime = data.runtime.records[Number(token.slice(8))]; return runtime ? { kind: 'runtime', title: 'Runtime Evidence 상세', value: runtime, runtime } : null }
  if (token.startsWith('candidate:')) { const [, run, id] = token.split(':'); const c = data.candidates.find(c => c.run_id === run && c.candidate_id === id); return c ? { kind: 'candidate', title: `${id} · 실행 근거`, value: c, trial: data.trials.find(t => t.run_id === run) } : null }
  const trial = data.trials.find(t => t.run_id === token)
  return trial ? { kind: 'trial', title: 'Trial Evidence 상세', value: trial, trial } : null
}

export default function App() {
  const [data, setData] = useState<Data | null>(null)
  const [error, setError] = useState('')
  const [params, setParams] = useState(() => new URLSearchParams(window.location.search))
  const [mobileNav, setMobileNav] = useState(false)
  const page = nav.find(n => n.id === params.get('view')) ?? nav[0]
  useEffect(() => { window.scrollTo(0, 0) }, [page.id])
  useEffect(() => { const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') setMobileNav(false) }; window.addEventListener('keydown', onKey); return () => window.removeEventListener('keydown', onKey) }, [])
  useEffect(() => { const controller = new AbortController(); fetch(`${base}data/guardon.json`, { signal: controller.signal }).then(r => { if (!r.ok) throw new Error('공개 데이터 파일을 읽을 수 없습니다.'); return r.json() }).then(value => setData(validateData(value as Data))).catch((e: unknown) => { if (!(e instanceof DOMException && e.name === 'AbortError')) setError(e instanceof Error ? e.message : '데이터 로딩 오류') }); return () => controller.abort() }, [])
  useEffect(() => { const onPop = () => setParams(new URLSearchParams(window.location.search)); window.addEventListener('popstate', onPop); return () => window.removeEventListener('popstate', onPop) }, [])
  function update(values: Record<string, string | null>, replace = false) { const next = new URLSearchParams(window.location.search); for (const [key, value] of Object.entries(values)) value === null || value === '' ? next.delete(key) : next.set(key, value); window.history[replace ? 'replaceState' : 'pushState']({}, '', `${window.location.pathname}?${next}`); setParams(next) }
  function go(view: string) { update({ view, q: null, run: null, source: null, condition: null, status: null, dataset: null, inspect: null }); setMobileNav(false) }
  const detail = useMemo(() => data ? resolveDetail(data, params.get('inspect')) : null, [data, params])
  const inspect: Inspect = token => update({ inspect: token }, true)
  return <div className="app-shell"><a className="skip-link" href="#main-content">본문으로 이동</a><aside className={`sidebar ${mobileNav ? 'is-open' : ''}`}><a className="brand" href="?view=overview" onClick={e => { e.preventDefault(); go('overview') }}><BrandMark /><span>GuardOn<span className="brand-sub">Security Research</span></span></a><div className="workspace"><span className="workspace-label">졸업 프로젝트</span><strong>Agent–MCP 보안 연구</strong></div><nav aria-label="주요 분석 화면">{nav.map(item => <a href={`?view=${item.id}`} key={item.id} className={page.id === item.id ? 'active' : ''} aria-current={page.id === item.id ? 'page' : undefined} onClick={e => { if (!e.metaKey && !e.ctrlKey && !e.shiftKey && e.button === 0) { e.preventDefault(); go(item.id) } }}><item.icon size={19} weight={page.id === item.id ? 'fill' : 'regular'} aria-hidden="true" /><span>{item.label}<small>{item.ko}</small></span>{page.id === item.id && <span className="nav-line" />}</a>)}</nav><div className="sidebar-footer"><button onClick={() => inspect('sources')}><Database size={17} aria-hidden="true" /><span>공개 실험 아카이브<small>12 samples · 48 attempts</small></span><CaretRight size={14} aria-hidden="true" /></button><div className="sidebar-mode"><span className="mode-dot" />Recorded / Replay<small>실시간 모델 호출 없음</small></div><ProjectCredit /></div></aside>
    <div className="main-shell"><header className="context-header"><button className="icon-button mobile-menu" aria-label="탐색 메뉴 열기" aria-expanded={mobileNav} onClick={() => setMobileNav(!mobileNav)}><List size={22} aria-hidden="true" /></button><div className="breadcrumbs"><span>GuardOn</span><CaretRight size={13} aria-hidden="true" /><strong>{page.label}</strong></div><div className="header-tools"><Search value={params.get('q') ?? ''} onChange={v => update({ q: v }, true)} onSearch={() => update({ view: 'evidence', source: null, run: null, inspect: null, condition: null, status: null, dataset: null })} /><span className="recorded-label"><span className="mode-dot" />Recorded</span><a className="freeze-ref" href="https://github.com/EHWA-Final-Project/ai-agent-security-middleware/tree/guardon-freeze-20261127" target="_blank" rel="noreferrer"><GitBranch size={15} aria-hidden="true" />Freeze <ArrowUpRight size={12} aria-hidden="true" /></a></div></header>
      <main id="main-content" tabIndex={-1}>{error ? <div className="load-error" role="alert"><Info size={28} /><h1>실험 데이터를 읽을 수 없습니다</h1><p>{error}</p><button className="button" onClick={() => window.location.reload()}>다시 불러오기</button></div> : !data ? <div className="loading" role="status" aria-label="공개 데이터 불러오는 중"><div /><div /><div /></div> : <>{page.id === 'overview' && <Overview data={data} params={params} inspect={inspect} go={go} />}{page.id === 'agent' && <Execution data={data} params={params} update={update} inspect={inspect} />}{page.id === 'comparison' && <Comparison data={data} params={params} update={update} inspect={inspect} />}{page.id === 'benchmark' && <Benchmark data={data} params={params} update={update} inspect={inspect} />}{page.id === 'evidence' && <Execution data={data} params={params} update={update} inspect={inspect} explorer />}</>}</main>
      <footer className="app-footer"><span><Check size={13} aria-hidden="true" />공개 관측 자료 · 읽기 전용</span><span>공식 ASR · TSR · FPR: N/A</span><a href={`${base}data/trial_observations.csv`} download="trial_observations.csv"><DownloadSimple size={14} aria-hidden="true" />Trial CSV</a></footer></div>
    {data && <DetailPanel detail={detail} data={data} close={() => update({ inspect: null }, true)} />}
  </div>
}
