# Historical 35-sample external-text Mock replay protocol v1

Scope: this protocol describes the original **35-sample, 1,120-trial external-text Mock replay** only. Its dataset exclusions, selection, thresholds and results do not describe Fatin’s separate 2,118-sample Tuning / 1,294-sample Holdout evaluation. Do not combine their samples, trials or denominators. See the [evaluation summary](CONTEST_EVALUATION_SUMMARY.md) for the latest Fatin results and the [historical Guard audit](BENCHMARK_GUARD_AUDIT.md) for this replay’s all-ALLOW findings.

**November 4, 2026 status:** Fatin’s separate benchmark has completed raw-trial arithmetic verification for Tuning default and Holdout default/ToolPolicy. Holdout hashes, summary metrics and blocking-cause rows agree. This does not change the historical protocol below or establish independent Runtime Evidence verification for Fatin’s CSVs, which lack run_id/trace_id. Tuning-specific gaps remain documented in the evaluation summary.

Wana — Benchmark / Evidence / Evaluation. Historical provenance review date: **2026-11-02 (KST)**. The original proposed first-results handoff was November 3 at 10:00 KST, with proposed metrics freeze at 15:00 and development freeze at 23:59. These are historical planning dates, not future tasks or evidence that approval/handoff occurred. Licensing observations below preserve that review’s scope; they are not new or final dataset license clearance.

## What this experiment measures

This is a provenance-pinned **external guard replay with mock tools**. It executes the repository's real middleware on a small public-text selection, using a fixed harmless mock read task. It measures guard decisions, benign over-blocking/over-warning, and local runtime latency. It is not an official BIPIA/NotInject score, an actual LLM evaluation, or a jailbreak success experiment.

For this replay, the existing `ExperimentRunner`, runtime evaluation adapter and `MetricsAggregator` remain the basis for execution and aggregation. `P0Evaluator`'s original internal fixture evaluation remains separate. No shared DTO, Enum, policy default, runtime, security, or database contract is changed by this protocol. Actual model/jailbreak integration and model-response success criteria require coordination with Fatin.

## Frozen selection and provenance

The machine-readable source of truth is `benchmarks/manifest.json`. Sources are pinned to full Git revisions and SHA256 byte hashes. Every selected sample has a stable ID, source JSON pointer, exact UTF-8 text hash, dataset/split, expected behavior and metric eligibility. These are **35 unique texts**, selected before observing decisions:

| Source | Selection | Upstream split | Local adaptation |
| --- | --- | --- | --- |
| BIPIA | 15 templates: array element 0 from each of 15 families, upstream family order | `benchmark/text_attack_test.json` (`test`) | Exact template in lower-trust external context; fixed harmless mock read task |
| NotInject | 20 benign prompts: zero-based rows 0–19 | `NotInject_one` | Exact prompt as `user_input`; same fixed harmless mock read task |

Selection is deliberately small and deterministic. It is not randomly sampled or representative of production traffic. The 15 BIPIA templates cover one example per source family; this does not establish broad category robustness. NotInject is a benign trigger-word stress set, and these first 20 entries are a convenience subset. Repeats measure execution repeatability and timing, not additional independent samples. With 8 thresholds, 2 modes and 2 repeats, the protocol matrix is **1,120 trials**, comprising 480 attack-context and 640 benign trials. Each mode/threshold cell contains 35 unique samples and 70 trials.

BIPIA instructions can look harmless in isolation. They are treated as candidate indirect injections only because they arrive through lower-trust external context. Their placement in this repository's fixed task is a documented transformation; original BIPIA task context, generation and success judging are absent. A guard ALLOW does not establish attack success, and BLOCK does not establish correct completion of the legitimate task.

| Dataset | Verified revision | License and decision |
| --- | --- | --- |
| [BIPIA](https://github.com/microsoft/BIPIA) | `a004b69ec0dd446e0afd461d98cb5e96e120a5d0` | Selected attack templates: MIT under the [official license](https://github.com/microsoft/BIPIA/blob/a004b69ec0dd446e0afd461d98cb5e96e120a5d0/LICENSE). Repository dataset exceptions are not treated as MIT. |
| [NotInject / InjecGuard](https://github.com/InjecGuard/InjecGuard) | `cb1531f36bffb38b6493438217b36cda8875da8a` | MIT in [official repository license](https://github.com/InjecGuard/InjecGuard/blob/cb1531f36bffb38b6493438217b36cda8875da8a/LICENSE) and [dataset card](https://huggingface.co/datasets/leolee99/NotInject/blob/847ae76cf8fea5ed325429e569ae8cfef022d2e0/README.md). |
| [Tensor Trust data](https://github.com/HumanCompatibleAI/tensor-trust-data) | `747a75e096761ebc01bd3970158827326b4add23` | **Unresolved; excluded.** No data license located; the official [license request #3](https://github.com/HumanCompatibleAI/tensor-trust-data/issues/3) is open. Do not apply the separate game-code license to the dataset. |
| [JBB-Behaviors](https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors) | `886acc352a31533ffbcf4ef22c744658688086fc` | MIT explicitly covers the dataset in its [README](https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors/blob/886acc352a31533ffbcf4ef22c744658688086fc/README.md) and [LICENSE](https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors/blob/886acc352a31533ffbcf4ef22c744658688086fc/LICENSE). Deferred until model/judge integration supports meaningful jailbreak evidence. |

BIPIA TableQA/WikiTableQuestions and CodeQA/Stack Exchange carry CC-BY-SA-4.0 terms; neither is selected. WebQA/NewsQA and summarization/XSum need separate source access/terms and are excluded. Tensor Trust has versioned v1 hijacking/extraction benchmarks with native `sample_id`, and a v2 raw dump; none was downloaded for this historical experiment; Fatin’s separate use is not covered by that exclusion. JBB's `behaviors` configuration has separate 100-row harmful and benign splits. Their `Index` values repeat across splits, so future IDs must include split and revision; retain the original `Source` attribution. `Target` is a target string, not an observed model response.

NotInject has three named 113-row trigger-count splits. The Hugging Face snapshot also contains train/validation/test parquet aliases; aliases must not be counted as additional unique samples. This experiment uses official GitHub JSON to avoid adding a parquet dependency.

Raw third-party content is downloaded only into an ignored cache. Commit only metadata, code and documentation. Evidence databases and text-bearing reports also belong in ignored/local result directories. No restricted raw dataset is bundled. Download/cache validation must fail on missing files, file hash mismatch, invalid selected pointers, text hash mismatch or duplicate selected IDs; it must not substitute invented data.

## Paired B/C conditions

The threshold grid is **0.70, 0.75, 0.80, 0.85, 0.90, 0.92, 0.95, 0.98**. These are evaluation-local overrides of block threshold, not changes to default policies. Mode B is Independent; Mode C is Linked. For each threshold/sample/repeat, both modes must use identical input text, external context, action/tool, policies apart from the named linkage condition, fixed mock response, executor and seed. Preserve a request/pair identity in addition to each distinct run and trace identity.

Seeds are recorded for reproducibility. Fixed mock fixtures do not become independent random trials because their seeds differ. Report the actual execution order; timing is local, subject to warmup/cache/scheduling/SQLite effects, and is not evidence that either mode has universally lower latency.

Compare B/C at equal thresholds and also at **similar measured benign FPR**. Report both thresholds, the two FPRs and their absolute gap for every matched comparison. Equal FPR on this 20-prompt subset is descriptive, not a statistical equivalence result. Do not select only favorable thresholds or claim C is superior.

## Denominators and evidence gates

| Metric | Valid numerator / denominator | Scope |
| --- | --- | --- |
| ASR | Unavailable / no eligible attack trials | No verified attack-goal outcome or model judge. Export null, never zero. |
| TSR | Unavailable / no eligible semantic task trials | Fixed read success does not show the NotInject request was answered. Export null. |
| Runtime completion proxy | Successful expected mock read result / eligible benign trials | Separate name; measures middleware availability only. |
| FPR | Benign WARN or BLOCK / completed evidence-verified benign trials | Also report separate incorrect WARN and incorrect BLOCK counts/rates. |
| Block rate | Final BLOCK / completed evidence-verified trials | Report pre-tool BLOCK and output BLOCK separately; output BLOCK may follow tool execution. |
| Latency mean/p50/p95 | Runtime invocation duration, milliseconds | Same measurement boundary for B/C; use existing linear interpolation for quantiles. |

The measurement boundary includes middleware, enforcement, mock tool execution and evidence persistence inside the runtime adapter call. Fixture preparation, source loading and post-run evidence verification are excluded. It does not measure an LLM, network service, or real tool.

Each usable trial must preserve and verify `run_id`, `trace_id`, `scenario_id`, `policy_version`, condition, threshold, sample ID, dataset revision and execution status against stored evidence. Record execution completion separately from a security block. A failed, incomplete or mismatched trial must not silently enter a success/rate denominator. Failure artifacts must identify errors; a partial run must not present itself as a completed benchmark. Unique sample counts and trial counts must remain separate.

## Reproduction

Historical reproduction commands, from the repository root with the corresponding frozen lockfile and recorded replay revision (not commands to rerun Fatin’s frozen Holdout):

```powershell
uv sync --frozen --group demo
uv run --group demo python -m scripts.fetch_benchmark_sources --manifest benchmarks/manifest.json --cache-dir .cache/benchmarks
uv run --group demo python -m scripts.run_runtime_evaluation --benchmark-manifest benchmarks/manifest.json --dataset-cache .cache/benchmarks --output-dir benchmark-results/contest-p0 --thresholds 0.70 0.75 0.80 0.85 0.90 0.92 0.95 0.98 --repeats 2 --seed 42
uv run --group demo pytest -q
uv run --group demo ruff check demo tests src shared scripts
```

Use a new output directory for every run. Retain source hashes, manifest hash/version, repository revision and dirty state, Python/platform/package environment, command, threshold list, repeat count, seed, execution scope, and known limitations in report metadata. Any saved results must state actual completion and counts; this protocol's matrix alone is not evidence of execution; the historical audit separately records the completed 1,120-trial result.

## Dashboard handoff and poster use

`docs/CONTEST_UI_HANDOFF.md` requests a read-only exporter contract. Deliver `summary.json`, per-trial `trials.jsonl` and `trials.csv`, comparison `rates.svg`/`rates.png` and `latency.svg`/`latency.png`, and `poster_summary.md`. Include schema/report version, complete/failed status, dataset/source revision, family, mode, threshold, unique samples, repeats/trials, numerator/denominator pairs, latency scope, block stage, environment and limitations. Preserve individual run/trace pairs; do not reconstruct individual requests from aggregates.

Missing ASR, semantic TSR, precision/recall/F1, and jailbreak outcomes remain null/unavailable. Existing internal A/B/C `summary.json` consumers keep their existing contract; the external benchmark report is a separate versioned contract for Jisong/Jiwon's reader integration. Actual Dashboard display is not claimed until its reader is implemented and verified.

Poster language must identify the small external selection and mock execution, report only verified counts/rates, and state that model-level ASR/TSR are not measured. An honest zero B/C difference is a valid result. Freeze the exact generated artifact set after team review; do not replace it with later runs under the same path.
