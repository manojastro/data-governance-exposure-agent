"""Evaluation-runner test: honest scoring against the planted ground truth.

The platform is EXPECTED to score 100% detection recall / precision and
exact-minimal remediation on seed 42 -- this test fails if the detectors or
planners regress.
"""
from __future__ import annotations

import pytest

from app.evaluation.runner import load_ground_truth, run_evaluation


@pytest.fixture(scope="module")
def evaluation_result():
    return run_evaluation(seed=42)


def test_ground_truth_file_loads():
    gt = load_ground_truth()
    assert len(gt["scenarios"]) == 17
    assert gt["thresholds"]["detection_recall"] == 1.0
    assert gt["thresholds"]["minimality_exact_ratio"] == 1.0
    assert gt["negative_guards"]["items"]


def test_detection_recall_is_perfect(evaluation_result):
    assert evaluation_result["detection_recall"] == 1.0


def test_detection_precision_is_perfect_no_false_positives(evaluation_result):
    assert evaluation_result["detection_precision"] == 1.0
    assert evaluation_result["false_positives"] == []


def test_minimality_exact_on_every_scenario(evaluation_result):
    assert evaluation_result["minimality_exact_matches"] == \
        evaluation_result["minimality_total"]
    imperfect = [s for s in evaluation_result["scenarios"]
                 if not (s["detected"] and s["type_match"] and s["minimality_exact"])]
    assert imperfect == []


def test_legitimacy_preserved_and_thresholds_pass(evaluation_result):
    assert evaluation_result["legitimacy_preserved"] is True
    assert evaluation_result["passed_thresholds"] is True


def test_shadow_exposure_drops_to_zero_in_evaluation(evaluation_result):
    assert evaluation_result["exposure_before"] == 17
    assert evaluation_result["exposure_after"] == 0
