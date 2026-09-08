import csv
from pathlib import Path

from sensitive_permissions.aws import live_validated_disclosure_documentation


TRACKER = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "AWS-service-security-review.csv"
)
VALID_STATUSES = {
    "queued",
    "in_progress",
    "no_new_positive",
    "validated",
    "blocked",
}


def _rows():
    with TRACKER.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_aws_service_review_tracker_is_complete_and_unique():
    rows = _rows()
    prefixes = [row["iam_prefix"] for row in rows]
    assert len(rows) == 455
    assert len(prefixes) == len(set(prefixes))
    assert {row["status"] for row in rows} <= VALID_STATUSES


def test_live_validated_aws_prefixes_are_not_left_queued():
    status_by_prefix = {row["iam_prefix"]: row["status"] for row in _rows()}
    evidence_prefixes = {
        action.split(":", 1)[0]
        for action in live_validated_disclosure_documentation
    }
    still_queued = sorted(
        prefix
        for prefix in evidence_prefixes
        if status_by_prefix.get(prefix) == "queued"
    )
    assert still_queued == []
