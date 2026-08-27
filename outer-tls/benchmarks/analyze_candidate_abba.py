#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Analyze counterbalanced baseline/candidate G301 benchmark sessions."""

from __future__ import annotations

import csv
import hashlib
import statistics
import sys
from collections import defaultdict
from pathlib import Path

import analyze_alpha_results as alpha


HASH_FIELDS = (
    "baseline_module_sha256",
    "candidate_module_sha256",
    "baseline_source_manifest_sha256",
    "candidate_source_manifest_sha256",
    "libcrypto_sha256",
    "benchmark_sha256",
    "compiler_sha256",
)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_source_snapshot(path: Path, expected_manifest_hash: str) -> None:
    manifest = path / "SOURCE_MANIFEST.sha256"
    if file_sha256(manifest) != expected_manifest_hash:
        raise ValueError(f"source-manifest hash mismatch: {path.name}")
    listed: set[Path] = set()
    for line_number, line in enumerate(
        manifest.read_text(encoding="utf-8").splitlines(), start=1
    ):
        fields = line.split(maxsplit=1)
        if len(fields) != 2 or len(fields[0]) != 64:
            raise ValueError(f"invalid source manifest at line {line_number}")
        relative = Path(fields[1])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"unsafe source path at line {line_number}")
        target = path / relative
        if not target.is_file() or target.is_symlink():
            raise ValueError(f"missing or non-regular source file: {relative}")
        if file_sha256(target) != fields[0]:
            raise ValueError(f"source hash mismatch: {relative}")
        if relative in listed:
            raise ValueError(f"duplicate source path: {relative}")
        listed.add(relative)


def resolve_relative(root: Path, value: str) -> Path:
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"non-relocatable path in RUNS.tsv: {value}")
    resolved = (root / relative).resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError(f"path escapes result root: {value}")
    return resolved


def median_ci(values: list[float], seed: int) -> tuple[float, float, float]:
    low, high = alpha.bootstrap_median_ci(values, seed)
    return statistics.median(values), low, high


def benefit_gate(absolute_low: float, relative_low: float) -> bool:
    return absolute_low > 0.0 and (absolute_low >= 8.0 or relative_low >= 5.0)


def no_regression_gate(improvement_low: float) -> bool:
    return improvement_low >= 0.0


def regression_budget_gate(regression_high: float, budget: float = 0.25) -> bool:
    return regression_high <= budget


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: analyze_candidate_abba.py RUNS.tsv OUTPUT_DIR")
    runs_path = Path(sys.argv[1])
    output_dir = Path(sys.argv[2])
    metadata: list[dict[str, str]] = []
    with runs_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        expected = {
            "lane", "pair", "slot", "variant", "cpu_mode", "sequence",
            "csv", *HASH_FIELDS,
        }
        if reader.fieldnames is None or set(reader.fieldnames) != expected:
            raise ValueError("unexpected RUNS.tsv schema")
        metadata.extend(reader)
    if not metadata:
        raise ValueError("empty RUNS.tsv")

    result_root = runs_path.resolve().parent
    lanes = {row["lane"] for row in metadata}
    if len(lanes) != 1:
        raise ValueError(f"RUNS.tsv must contain exactly one lane: {lanes}")
    fixed = {field: {row[field] for row in metadata} for field in HASH_FIELDS}
    for field, values in fixed.items():
        if len(values) != 1:
            raise ValueError(f"inconsistent {field}: {values}")
        value = next(iter(values))
        if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ValueError(f"invalid SHA-256 in {field}")

    baseline_hash = next(iter(fixed["baseline_module_sha256"]))
    candidate_hash = next(iter(fixed["candidate_module_sha256"]))
    benchmark_hash = next(iter(fixed["benchmark_sha256"]))
    if file_sha256(result_root / "modules/baseline/g301.so") != baseline_hash:
        raise ValueError("baseline module hash mismatch")
    if file_sha256(result_root / "modules/candidate/g301.so") != candidate_hash:
        raise ValueError("candidate module hash mismatch")
    if file_sha256(result_root / "g301_alpha_benchmark") != benchmark_hash:
        raise ValueError("benchmark binary hash mismatch")
    verify_source_snapshot(
        result_root / "source/baseline",
        next(iter(fixed["baseline_source_manifest_sha256"])),
    )
    verify_source_snapshot(
        result_root / "source/candidate",
        next(iter(fixed["candidate_source_manifest_sha256"])),
    )

    identities: set[tuple[str, int, int, str]] = set()
    schedule: dict[tuple[str, int], list[dict[str, str]]] = defaultdict(list)
    for item in metadata:
        if item["variant"] not in {"baseline", "candidate"}:
            raise ValueError(f"invalid variant: {item['variant']}")
        if item["cpu_mode"] not in {"native", "aes_accel_masked"}:
            raise ValueError(f"invalid CPU mode: {item['cpu_mode']}")
        pair = int(item["pair"])
        slot = int(item["slot"])
        identity = (item["cpu_mode"], pair, slot, item["variant"])
        if identity in identities:
            raise ValueError(f"duplicate run identity: {identity}")
        identities.add(identity)
        schedule[(item["cpu_mode"], pair)].append(item)
    pair_numbers = sorted({int(row["pair"]) for row in metadata})
    if len(pair_numbers) < 8 or pair_numbers != list(range(len(pair_numbers))):
        raise ValueError(f"invalid pair sequence: {pair_numbers}")
    for cpu_mode in ("native", "aes_accel_masked"):
        for pair in pair_numbers:
            rows = sorted(schedule[(cpu_mode, pair)], key=lambda row: int(row["slot"]))
            expected_variants = (
                ["baseline", "candidate", "candidate", "baseline"]
                if pair % 2 == 0
                else ["candidate", "baseline", "baseline", "candidate"]
            )
            expected_sequence = "ABBA" if pair % 2 == 0 else "BAAB"
            if (
                [int(row["slot"]) for row in rows] != [0, 1, 2, 3]
                or [row["variant"] for row in rows] != expected_variants
                or {row["sequence"] for row in rows} != {expected_sequence}
            ):
                raise ValueError(f"invalid schedule for {cpu_mode} pair {pair}")

    process_metrics: dict[tuple[object, ...], float] = {}
    pair_members: dict[tuple[object, ...], list[float]] = defaultdict(list)
    for item in metadata:
        path = resolve_relative(result_root, item["csv"])
        observations = alpha.load([path])
        alpha.validate(observations)
        paired: dict[tuple[str, int, int], dict[str, float]] = defaultdict(dict)
        for row in observations:
            key = (str(row["direction"]), int(row["payload_size"]), int(row["sample"]))
            paired[key][str(row["path"])] = float(row["ns"])
        by_cell_wrapper: dict[tuple[str, int], list[float]] = defaultdict(list)
        by_cell_g301: dict[tuple[str, int], list[float]] = defaultdict(list)
        for (direction, payload, _sample), paths in paired.items():
            by_cell_wrapper[(direction, payload)].append(
                paths["g301_a"] - paths["default_split_ma"]
            )
            by_cell_g301[(direction, payload)].append(paths["g301_a"])
        identity = (
            item["lane"],
            int(item["pair"]),
            int(item["slot"]),
            item["variant"],
            item["cpu_mode"],
        )
        for cell, values in by_cell_wrapper.items():
            process_metrics[identity + ("wrapper",) + cell] = statistics.median(values)
        for cell, values in by_cell_g301.items():
            process_metrics[identity + ("g301",) + cell] = statistics.median(values)

    for key, value in process_metrics.items():
        lane, pair, _slot, variant, cpu_mode, metric, direction, payload = key
        pair_members[(lane, pair, variant, cpu_mode, metric, direction, payload)].append(value)
    for key, values in pair_members.items():
        if len(values) != 2:
            raise ValueError(f"ABBA pair does not contain two process values: {key}")

    pair_values = {key: statistics.fmean(values) for key, values in pair_members.items()}
    effects: dict[tuple[str, str, str, str, int], list[float]] = defaultdict(list)
    baseline_values: dict[tuple[str, str, str, str, int], list[float]] = defaultdict(list)
    pairs = sorted({(str(row["lane"]), int(row["pair"]), row["cpu_mode"]) for row in metadata})
    pair_rows: list[dict[str, object]] = []
    for lane, pair, cpu_mode in pairs:
        for direction in ("encrypt", "decrypt"):
            for payload in (1, 16, 1024, 16385):
                base_wrapper = pair_values[(lane, pair, "baseline", cpu_mode, "wrapper", direction, payload)]
                cand_wrapper = pair_values[(lane, pair, "candidate", cpu_mode, "wrapper", direction, payload)]
                base_g301 = pair_values[(lane, pair, "baseline", cpu_mode, "g301", direction, payload)]
                cand_g301 = pair_values[(lane, pair, "candidate", cpu_mode, "g301", direction, payload)]
                improvement = base_wrapper - cand_wrapper
                regression_pct = (cand_g301 / base_g301 - 1.0) * 100.0
                effects[(lane, cpu_mode, "wrapper_improvement_ns", direction, payload)].append(improvement)
                baseline_values[(lane, cpu_mode, "wrapper_improvement_ns", direction, payload)].append(base_wrapper)
                effects[(lane, cpu_mode, "g301_regression_pct", direction, payload)].append(regression_pct)
                pair_rows.append({
                    "lane": lane,
                    "pair": pair,
                    "cpu_mode": cpu_mode,
                    "direction": direction,
                    "payload_size": payload,
                    "baseline_wrapper_ns": base_wrapper,
                    "candidate_wrapper_ns": cand_wrapper,
                    "wrapper_improvement_ns": improvement,
                    "baseline_g301_ns": base_g301,
                    "candidate_g301_ns": cand_g301,
                    "g301_regression_pct": regression_pct,
                })

    with (output_dir / "pair_metrics.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(pair_rows[0]))
        writer.writeheader()
        writer.writerows(pair_rows)

    summary_rows: list[dict[str, object]] = []
    for index, key in enumerate(sorted(effects)):
        lane, cpu_mode, metric, direction, payload = key
        median, low, high = median_ci(effects[key], 7301 + index)
        baseline = baseline_values.get(key)
        summary_rows.append({
            "lane": lane,
            "cpu_mode": cpu_mode,
            "metric": metric,
            "direction": direction,
            "payload_size": payload,
            "pairs": len(effects[key]),
            "median": median,
            "ci95_low": low,
            "ci95_high": high,
            "baseline_median_ns": statistics.median(baseline) if baseline else "",
            "median_improvement_pct": (
                median / statistics.median(baseline) * 100.0 if baseline else ""
            ),
        })

    decisions: list[str] = []
    lane = str(metadata[0]["lane"])
    gate_pass = True
    pair_numbers = sorted({int(row["pair"]) for row in metadata})

    pooled_effects: list[float] = []
    pooled_baselines: list[float] = []
    for pair in pair_numbers:
        improvements = []
        baselines = []
        for direction in ("encrypt", "decrypt"):
            for payload in (1, 16):
                base = pair_values[(lane, pair, "baseline", "native", "wrapper", direction, payload)]
                cand = pair_values[(lane, pair, "candidate", "native", "wrapper", direction, payload)]
                improvements.append(base - cand)
                baselines.append(base)
        pooled_effects.append(statistics.fmean(improvements))
        pooled_baselines.append(statistics.fmean(baselines))
    median, low, high = median_ci(pooled_effects, 8301)
    relative_effects = [
        effect / base * 100.0
        for effect, base in zip(pooled_effects, pooled_baselines, strict=True)
    ]
    relative_median, relative_low, relative_high = median_ci(
        relative_effects, 8801
    )
    baseline = statistics.median(pooled_baselines)
    percent = median / baseline * 100.0
    passed = benefit_gate(low, relative_low)
    gate_pass = gate_pass and passed
    decisions.append(
        f"- native pooled fixed wrapper: {median:.3f} ns ({percent:.2f}%), "
        f"95% CI [{low:.3f}, {high:.3f}]; paired relative median "
        f"{relative_median:.2f}% (95% CI [{relative_low:.2f}, "
        f"{relative_high:.2f}]) -> {'PASS' if passed else 'FAIL'}"
    )

    for cpu_mode in ("native", "aes_accel_masked"):
        for direction in ("encrypt", "decrypt"):
            cell_effects: list[float] = []
            cell_baselines: list[float] = []
            for pair in pair_numbers:
                improvements = []
                baselines = []
                for payload in (1, 16):
                    base = pair_values[(lane, pair, "baseline", cpu_mode, "wrapper", direction, payload)]
                    cand = pair_values[(lane, pair, "candidate", cpu_mode, "wrapper", direction, payload)]
                    improvements.append(base - cand)
                    baselines.append(base)
                cell_effects.append(statistics.fmean(improvements))
                cell_baselines.append(statistics.fmean(baselines))
            median, low, high = median_ci(cell_effects, 9301 + len(decisions))
            baseline = statistics.median(cell_baselines)
            percent = median / baseline * 100.0
            passed = no_regression_gate(low)
            gate_pass = gate_pass and passed
            decisions.append(
                f"- {cpu_mode} {direction}: {median:.3f} ns ({percent:.2f}%), "
                f"95% CI [{low:.3f}, {high:.3f}], no reliable regression "
                f"-> {'PASS' if passed else 'FAIL'}"
            )
        for direction in ("encrypt", "decrypt"):
            large = effects[(lane, cpu_mode, "g301_regression_pct", direction, 16385)]
            median, low, high = median_ci(large, 11301 + len(decisions))
            passed = regression_budget_gate(high)
            gate_pass = gate_pass and passed
            decisions.append(
                f"- {cpu_mode} {direction} 16385-byte regression: {median:.3f}% "
                f"(95% CI [{low:.3f}, {high:.3f}]) -> {'PASS' if passed else 'FAIL'}"
            )

    with (output_dir / "summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summary_rows[0]))
        writer.writeheader()
        writer.writerows(summary_rows)
    (output_dir / "DECISION.md").write_text(
        "# Candidate acceptance decision\n\n"
        f"Lane: OpenSSL {lane}\n\n"
        + "\n".join(decisions)
        + f"\n\nCANDIDATE LANE DISPOSITION: {'ACCEPT' if gate_pass else 'REJECT'}\n",
        encoding="utf-8",
    )
    if not gate_pass:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
