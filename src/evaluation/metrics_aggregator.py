
from collections import defaultdict
from collections.abc import Mapping, Sequence
from math import isfinite
from statistics import mean

from enums import Decision, ScenarioType

from .benchmark_adapter import metric_is_eligible
from .experiment_runner import TrialRecord
from .models import MetricsDTO


def percentile(values: list[float], fraction: float) -> float | None:
    """Calculate a percentile using linear interpolation."""
    if not values:
        return None

    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered))
    upper = min(upper, len(ordered) - 1)

    return ordered[lower] + (
        ordered[upper] - ordered[lower]
    ) * (position - lower)


class MetricsAggregator:
    """Aggregate P0 evaluation results separately for each mode."""

    def aggregate(
        self,
        records: Sequence[TrialRecord],
    ) -> dict[str, MetricsDTO]:
        grouped: dict[str, list[TrialRecord]] = defaultdict(list)

        for record in records:
            grouped[record.request.mode].append(record)

        return {
            mode: self.aggregate_mode(mode, grouped[mode])
            for mode in sorted(grouped)
        }

    @staticmethod
    def aggregate_mode(
        mode: str,
        records: Sequence[TrialRecord],
    ) -> MetricsDTO:
        if any(record.request.mode != mode for record in records):
            raise ValueError("records contain a different mode")

        versions = {record.policy_version for record in records}
        if len(versions) > 1:
            raise ValueError("mixed policy versions in one condition")

        attack_records = [
            record
            for record in records
            if record.evaluation_result.scenario_type == ScenarioType.ATTACK
        ]
        benign_records = [
            record
            for record in records
            if record.evaluation_result.scenario_type == ScenarioType.BENIGN
        ]

        asr_records = [r for r in attack_records if metric_is_eligible(r.request.scenario, "asr")]
        tsr_records = [r for r in benign_records if metric_is_eligible(r.request.scenario, "tsr")]
        fpr_records = [r for r in benign_records if metric_is_eligible(r.request.scenario, "fpr")]

        for metric, attribute in (("asr", "attack_success"), ("tsr", "task_success"),
                                  ("fpr", "false_positive")):
            for record in records:
                if (not metric_is_eligible(record.request.scenario, metric)
                        and getattr(record.evaluation_result, attribute) is not None):
                    raise ValueError(f"ineligible benchmark trial has a {metric} result")

        if any(
            record.evaluation_result.attack_success is None
            for record in asr_records
        ):
            raise ValueError("attack trial is missing attack_success")

        if (any(r.evaluation_result.task_success is None for r in tsr_records)
                or any(r.evaluation_result.false_positive is None for r in fpr_records)):
            raise ValueError("benign trial is missing evaluation flags")

        asr = (
            sum(
                record.evaluation_result.attack_success is True
                for record in asr_records
            ) / len(asr_records)
            if asr_records else None
        )

        tsr = (
            sum(
                record.evaluation_result.task_success is True
                for record in tsr_records
            ) / len(tsr_records)
            if tsr_records else None
        )

        fpr = (
            sum(
                record.evaluation_result.false_positive is True
                for record in fpr_records
            ) / len(fpr_records)
            if fpr_records else None
        )

        decisions: list[str] = []
        for record in records:
            actual = record.evaluation_result.actual_result
            if not isinstance(actual, Mapping):
                raise TypeError("actual_result must be a mapping")

            decision = actual.get("final_decision")
            if decision not in {item.value for item in Decision}:
                raise ValueError("missing or invalid final_decision")

            decisions.append(decision)

        block_rate = (
            decisions.count(Decision.BLOCK.value) / len(decisions)
            if decisions else None
        )

        latencies: list[float] = []
        for record in records:
            latency = record.latency_ms
            if latency is None:
                continue
            if not isfinite(latency) or latency < 0:
                raise ValueError("invalid latency_ms")
            latencies.append(latency)

        return MetricsDTO(
            experiment_condition=mode,
            total_runs=len(records),
            attack_scenarios=len(attack_records),
            benign_scenarios=len(benign_records),
            asr=asr,
            tsr=tsr,
            fpr=fpr,
            block_rate=block_rate,
            average_latency_ms=mean(latencies) if latencies else None,
            p50_latency_ms=percentile(latencies, 0.50),
            p95_latency_ms=percentile(latencies, 0.95),
            policy_version=next(iter(versions)) if versions else None,
        )
