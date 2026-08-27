#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for fail-closed benchmark decision boundaries."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))

import analyze_candidate_abba as gate  # noqa: E402


def main() -> None:
    assert gate.benefit_gate(8.0, 0.1)
    assert gate.benefit_gate(0.1, 5.0)
    assert not gate.benefit_gate(-0.1, 10.0)
    assert not gate.benefit_gate(7.9, 4.9)
    assert gate.no_regression_gate(0.0)
    assert not gate.no_regression_gate(-0.001)
    assert gate.regression_budget_gate(0.25)
    assert not gate.regression_budget_gate(0.251)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory).resolve()
        assert gate.resolve_relative(root, "raw/run.csv") == root / "raw/run.csv"
        for unsafe in ("/tmp/run.csv", "../run.csv", "raw/../../run.csv"):
            try:
                gate.resolve_relative(root, unsafe)
            except ValueError:
                pass
            else:
                raise AssertionError(f"unsafe path accepted: {unsafe}")


if __name__ == "__main__":
    main()
