#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Validate and summarize paired G301 EVP benchmark observations."""

from __future__ import annotations

import argparse
import csv
import math
import random
import statistics
from collections import Counter, defaultdict
from pathlib import Path


PATHS = (
    "default_a",
    "default_ma_prebuilt",
    "default_split_ma",
    "g301_a",
)
REQUIRED_FIELDS = {
    "mode",
    "direction",
    "path",
    "payload_size",
    "warmup_records",
    "records_per_sample",
    "sample_index",
    "position",
    "elapsed_ns",
    "ns_per_record",
    "throughput_mib_s",
    "checksum",
}
COMPARISONS = (
    ("total_profile", "g301_a", "default_a"),
    ("manifest_aad", "default_ma_prebuilt", "default_a"),
    ("split_aad_calls", "default_split_ma", "default_ma_prebuilt"),
    ("wrapper_api", "g301_a", "default_split_ma"),
)


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        raise ValueError("percentile of empty sequence")
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def bootstrap_median_ci(values: list[float], seed: int) -> tuple[float, float]:
    rng = random.Random(seed)
    count = len(values)
    medians = [
        statistics.median(values[rng.randrange(count)] for _ in range(count))
        for _ in range(10_000)
    ]
    return percentile(medians, 0.025), percentile(medians, 0.975)


def load(paths: list[Path]) -> list[dict[str, object]]:
    observations: list[dict[str, object]] = []
    for run_index, path in enumerate(paths):
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None or set(reader.fieldnames) != REQUIRED_FIELDS:
                raise ValueError(f"unexpected CSV schema in {path}")
            for line_number, row in enumerate(reader, start=2):
                if row["path"] not in PATHS:
                    raise ValueError(
                        f"unknown path in {path}:{line_number}: {row['path']}"
                    )
                parsed: dict[str, object] = {
                    "run": run_index,
                    "source": path.name,
                    "mode": row["mode"],
                    "direction": row["direction"],
                    "path": row["path"],
                    "payload_size": int(row["payload_size"]),
                    "warmup_records": int(row["warmup_records"]),
                    "records": int(row["records_per_sample"]),
                    "sample": int(row["sample_index"]),
                    "position": int(row["position"]),
                    "elapsed_ns": int(row["elapsed_ns"]),
                    "ns": float(row["ns_per_record"]),
                    "throughput": float(row["throughput_mib_s"]),
                    "checksum": int(row["checksum"], 16),
                }
                if int(parsed["records"]) <= 0 or int(parsed["elapsed_ns"]) <= 0:
                    raise ValueError(f"non-positive timing in {path}:{line_number}")
                expected_elapsed = float(parsed["ns"]) * int(parsed["records"])
                tolerance = max(1.0, int(parsed["records"]) * 0.00001)
                if abs(int(parsed["elapsed_ns"]) - expected_elapsed) > tolerance:
                    raise ValueError(f"inconsistent elapsed time in {path}:{line_number}")
                observations.append(parsed)
    if not observations:
        raise ValueError("no input rows")
    return observations


def validate(observations: list[dict[str, object]]) -> int:
    paired: dict[tuple[object, ...], dict[str, dict[str, object]]] = defaultdict(dict)
    position_counts: dict[tuple[object, ...], Counter[tuple[str, int]]] = defaultdict(Counter)
    sample_sets: dict[tuple[object, ...], set[int]] = defaultdict(set)

    for row in observations:
        group = (
            row["run"],
            row["mode"],
            row["direction"],
            row["payload_size"],
            row["sample"],
        )
        path = str(row["path"])
        if path in paired[group]:
            raise ValueError(f"duplicate path in paired sample {group}: {path}")
        paired[group][path] = row
        balance_group = group[:-1]
        position_counts[balance_group][(path, int(row["position"]))] += 1
        sample_sets[balance_group].add(int(row["sample"]))

    for group, rows in paired.items():
        if set(rows) != set(PATHS):
            raise ValueError(f"incomplete paired sample {group}: {sorted(rows)}")
        if {int(row["position"]) for row in rows.values()} != set(range(len(PATHS))):
            raise ValueError(f"invalid Latin-square positions in {group}")
        checksums = {path: int(rows[path]["checksum"]) for path in PATHS}
        if any(value == 0 for value in checksums.values()):
            raise ValueError(f"zero checksum in {group}")
        if not (
            checksums["default_ma_prebuilt"]
            == checksums["default_split_ma"]
            == checksums["g301_a"]
        ):
            raise ValueError(f"equivalent-path checksum mismatch in {group}")
        if checksums["default_a"] == checksums["g301_a"]:
            raise ValueError(f"profile-separation checksum collision in {group}")

    for group, counts in position_counts.items():
        sample_count = len(sample_sets[group])
        if sample_count < 8 or sample_count % len(PATHS) != 0:
            raise ValueError(f"invalid sample count for {group}: {sample_count}")
        expected = sample_count // len(PATHS)
        for path in PATHS:
            for position in range(len(PATHS)):
                if counts[(path, position)] != expected:
                    raise ValueError(
                        f"unbalanced Latin square for {group}: "
                        f"{path} at {position} = {counts[(path, position)]}, "
                        f"expected {expected}"
                    )
    return len(paired)


def write_summary(observations: list[dict[str, object]], output: Path) -> None:
    groups: dict[tuple[str, str, str, int], list[float]] = defaultdict(list)
    for row in observations:
        key = (
            str(row["mode"]),
            str(row["direction"]),
            str(row["path"]),
            int(row["payload_size"]),
        )
        groups[key].append(float(row["ns"]))

    rows: list[dict[str, object]] = []
    for key in sorted(groups):
        values = groups[key]
        mode, direction, path, payload_size = key
        rows.append(
            {
                "mode": mode,
                "direction": direction,
                "path": path,
                "payload_size": payload_size,
                "samples": len(values),
                "min_ns": min(values),
                "p05_ns": percentile(values, 0.05),
                "p25_ns": percentile(values, 0.25),
                "median_ns": statistics.median(values),
                "p75_ns": percentile(values, 0.75),
                "p95_ns": percentile(values, 0.95),
                "max_ns": max(values),
                "mean_ns": statistics.fmean(values),
                "stdev_ns": statistics.stdev(values) if len(values) > 1 else 0.0,
            }
        )
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def write_comparisons(observations: list[dict[str, object]], output: Path) -> None:
    paired: dict[tuple[object, ...], dict[str, float]] = defaultdict(dict)
    for row in observations:
        key = (
            row["run"],
            row["mode"],
            row["direction"],
            row["payload_size"],
            row["sample"],
        )
        paired[key][str(row["path"])] = float(row["ns"])

    deltas: dict[tuple[str, str, int, str], list[float]] = defaultdict(list)
    ratios: dict[tuple[str, str, int, str], list[float]] = defaultdict(list)
    run_counts: dict[tuple[str, str, int, str], set[int]] = defaultdict(set)
    for key, values in paired.items():
        run, mode, direction, payload_size, _sample = key
        for name, minuend, subtrahend in COMPARISONS:
            result_key = (str(mode), str(direction), int(payload_size), name)
            deltas[result_key].append(values[minuend] - values[subtrahend])
            ratios[result_key].append(
                (values[minuend] / values[subtrahend] - 1.0) * 100.0
            )
            run_counts[result_key].add(int(run))

    rows: list[dict[str, object]] = []
    for index, key in enumerate(sorted(deltas)):
        mode, direction, payload_size, name = key
        values = deltas[key]
        low, high = bootstrap_median_ci(values, 301_000 + index)
        rows.append(
            {
                "mode": mode,
                "direction": direction,
                "payload_size": payload_size,
                "comparison": name,
                "runs": len(run_counts[key]),
                "paired_samples": len(values),
                "median_delta_ns": statistics.median(values),
                "bootstrap_median_ci95_low_ns": low,
                "bootstrap_median_ci95_high_ns": high,
                "median_delta_pct": statistics.median(ratios[key]),
            }
        )
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--comparisons", required=True, type=Path)
    parser.add_argument("--validation", required=True, type=Path)
    args = parser.parse_args()

    observations = load(args.inputs)
    paired_samples = validate(observations)
    write_summary(observations, args.summary)
    write_comparisons(observations, args.comparisons)
    args.validation.write_text(
        "VALIDATION: PASS\n"
        f"input_files={len(args.inputs)}\n"
        f"rows={len(observations)}\n"
        f"paired_samples={paired_samples}\n"
        "paths=" + ",".join(PATHS) + "\n"
        "design=balanced_4x4_latin_square\n"
        "comparison=paired_per_sample_with_10000x_bootstrap_median_ci\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
