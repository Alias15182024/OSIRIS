"""Unit tests for OSIRIS ResourcesSummaryCardsFrame and find_latest_resource_snapshot.

Verifies:
1. find_latest_resource_snapshot correctly determines newest snapshot.
2. Does not assume chronological collection ordering.
3. Handles empty, single-element, and None snapshot inputs safely.
4. ResourcesSummaryCardsFrame construction and child MetricCard layout.
5. All 4 metrics accurately derived from latest snapshot:
   - CPU %
   - Memory %
   - Disk %
   - Memory Used vs Memory Total
6. Memory Used / Total combinations (both present, used only, total only, neither).
7. Nullable percentage and byte values displayed as neutral placeholders.
8. Numeric zero preserved across all metrics (0.0%, 0 B).
9. Clearing or setting None resets cards and hides detail labels.
10. update_from_collection and update_from_snapshots APIs.
11. No HTTP, backend, database, or network modules are imported.
"""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from desktop.client.models import ResourceSnapshot, ResourceSnapshotCollection
from desktop.models.resources_model import (
    EMPTY_PLACEHOLDER,
    find_latest_resource_snapshot,
    format_bytes,
    format_percent,
)
from desktop.ui.components import MetricCard, ResourcesSummaryCardsFrame

SAMPLE_SNAPSHOT_ID_1 = "11111111-1111-4111-8111-111111111111"
SAMPLE_SNAPSHOT_ID_2 = "22222222-2222-4222-8222-222222222222"
SAMPLE_SNAPSHOT_ID_3 = "33333333-3333-4333-8333-333333333333"
SAMPLE_HOST_ID = "44444444-4444-4444-8444-444444444444"

TIME_EARLY = "2026-03-01T08:00:00Z"
TIME_MID = "2026-03-01T08:05:00Z"
TIME_LATE = "2026-03-01T08:10:00Z"


def _make_snapshot(
    snapshot_id: str = SAMPLE_SNAPSHOT_ID_1,
    timestamp: str = TIME_MID,
    created_at: str = TIME_MID,
    cpu_percent: float | None = 20.0,
    memory_percent: float | None = 40.0,
    disk_usage_percent: float | None = 60.0,
    memory_used: int | None = 4_294_967_296,  # 4 GiB
    memory_total: int | None = 17_179_869_184,  # 16 GiB
) -> ResourceSnapshot:
    """Create a ResourceSnapshot instance for summary card testing."""
    return ResourceSnapshot(
        id=snapshot_id,
        host_id=SAMPLE_HOST_ID,
        timestamp=timestamp,
        created_at=created_at,
        cpu_percent=cpu_percent,
        memory_percent=memory_percent,
        disk_usage_percent=disk_usage_percent,
        memory_used=memory_used,
        memory_total=memory_total,
        disk_read_bytes=1048576,
        disk_write_bytes=2097152,
    )


# ==============================================================================
# 1. find_latest_resource_snapshot Algorithm Tests
# ==============================================================================


def test_find_latest_empty_or_none() -> None:
    """find_latest_resource_snapshot returns None for empty or None sequences."""
    assert find_latest_resource_snapshot(None) is None
    assert find_latest_resource_snapshot([]) is None
    assert find_latest_resource_snapshot(()) is None


def test_find_latest_single_item() -> None:
    """find_latest_resource_snapshot returns the single snapshot provided."""
    snap = _make_snapshot(timestamp=TIME_MID)
    assert find_latest_resource_snapshot([snap]) is snap


def test_find_latest_chronological_order() -> None:
    """find_latest_resource_snapshot returns the newest in chronological list."""
    s1 = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_1, timestamp=TIME_EARLY)
    s2 = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_2, timestamp=TIME_MID)
    s3 = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_3, timestamp=TIME_LATE)

    result = find_latest_resource_snapshot([s1, s2, s3])
    assert result is s3


def test_find_latest_reverse_chronological_order() -> None:
    """find_latest_resource_snapshot returns newest when list is descending."""
    s1 = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_1, timestamp=TIME_EARLY)
    s2 = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_2, timestamp=TIME_MID)
    s3 = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_3, timestamp=TIME_LATE)

    result = find_latest_resource_snapshot([s3, s2, s1])
    assert result is s3


def test_find_latest_arbitrary_unassumed_order() -> None:
    """find_latest_resource_snapshot finds newest regardless of permutation."""
    s1 = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_1, timestamp=TIME_EARLY)
    s2 = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_2, timestamp=TIME_LATE)
    s3 = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_3, timestamp=TIME_MID)

    result = find_latest_resource_snapshot([s1, s2, s3])
    assert result is s2


def test_find_latest_generator_and_empty_generator() -> None:
    """find_latest_resource_snapshot handles generators without crashing."""
    empty_list: list[ResourceSnapshot] = []
    assert find_latest_resource_snapshot(s for s in empty_list) is None

    s1 = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_1, timestamp=TIME_EARLY)
    s2 = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_2, timestamp=TIME_LATE)
    gen = (s for s in [s1, s2])
    assert find_latest_resource_snapshot(gen) is s2


def test_find_latest_timezone_offsets_normalized() -> None:
    """find_latest_resource_snapshot normalizes timezone offsets accurately."""
    # 12:00:00 UTC vs 17:31:00 +05:30 (12:01:00 UTC -> 1 minute later)
    s_utc = _make_snapshot(
        snapshot_id=SAMPLE_SNAPSHOT_ID_1,
        timestamp="2026-03-01T12:00:00Z",
    )
    s_ist = _make_snapshot(
        snapshot_id=SAMPLE_SNAPSHOT_ID_2,
        timestamp="2026-03-01T17:31:00+05:30",
    )
    assert find_latest_resource_snapshot([s_utc, s_ist]) is s_ist
    assert find_latest_resource_snapshot([s_ist, s_utc]) is s_ist


def test_find_latest_identical_timestamp_breaks_tie_with_created_at() -> None:
    """When observation timestamps are equal, created_at determines newest."""
    s1 = _make_snapshot(
        snapshot_id=SAMPLE_SNAPSHOT_ID_1,
        timestamp=TIME_MID,
        created_at="2026-03-01T08:05:01Z",
    )
    s2 = _make_snapshot(
        snapshot_id=SAMPLE_SNAPSHOT_ID_2,
        timestamp=TIME_MID,
        created_at="2026-03-01T08:05:05Z",
    )
    assert find_latest_resource_snapshot([s1, s2]) is s2
    assert find_latest_resource_snapshot([s2, s1]) is s2


def test_find_latest_unparseable_timestamps_lexical_fallback() -> None:
    """When timestamps are non-standard/unparseable, lexical fallback is used."""
    s1 = _make_snapshot(
        snapshot_id=SAMPLE_SNAPSHOT_ID_1,
        timestamp="invalid-timestamp-2026-01",
        created_at="invalid-created-2026-01",
    )
    s2 = _make_snapshot(
        snapshot_id=SAMPLE_SNAPSHOT_ID_2,
        timestamp="invalid-timestamp-2026-02",
        created_at="invalid-created-2026-02",
    )
    assert find_latest_resource_snapshot([s1, s2]) is s2
    assert find_latest_resource_snapshot([s2, s1]) is s2


def test_format_percent_nan_inf_and_negative() -> None:
    """format_percent returns EMPTY_PLACEHOLDER for NaN, Inf, and negatives."""
    assert format_percent(float("nan")) == EMPTY_PLACEHOLDER
    assert format_percent(float("inf")) == EMPTY_PLACEHOLDER
    assert format_percent(float("-inf")) == EMPTY_PLACEHOLDER
    assert format_percent(-5.0) == EMPTY_PLACEHOLDER
    assert format_percent(0.0) == "0.0%"
    assert format_percent(99.9) == "99.9%"


def test_format_bytes_nan_and_invalid_types() -> None:
    """format_bytes returns EMPTY_PLACEHOLDER for NaN, floats, and non-ints."""
    assert format_bytes(float("nan")) == EMPTY_PLACEHOLDER  # type: ignore[arg-type]
    assert format_bytes(1024.5) == EMPTY_PLACEHOLDER  # type: ignore[arg-type]
    assert format_bytes(-10) == EMPTY_PLACEHOLDER
    assert format_bytes(True) == EMPTY_PLACEHOLDER
    assert format_bytes(0) == "0 B"


# ==============================================================================
# 2. ResourcesSummaryCardsFrame Construction and Layout
# ==============================================================================


def test_summary_cards_frame_construction(qapp: QApplication) -> None:
    """ResourcesSummaryCardsFrame constructs cleanly with 4 metric cards."""
    frame = ResourcesSummaryCardsFrame()
    assert frame.objectName() == "ResourcesSummaryCardsFrame"
    assert frame.current_snapshot is None

    assert isinstance(frame.cpu_card, MetricCard)
    assert isinstance(frame.memory_card, MetricCard)
    assert isinstance(frame.disk_card, MetricCard)
    assert isinstance(frame.memory_used_total_card, MetricCard)
    assert frame.memory_allocation_card is frame.memory_used_total_card

    # Initial values are neutral placeholders
    assert frame.cpu_card.value == EMPTY_PLACEHOLDER
    assert frame.memory_card.value == EMPTY_PLACEHOLDER
    assert frame.disk_card.value == EMPTY_PLACEHOLDER
    assert frame.memory_used_total_card.value == EMPTY_PLACEHOLDER

    # Initial details are cleared
    assert frame.cpu_card.detail is None
    assert frame.memory_card.detail is None
    assert frame.disk_card.detail is None
    assert frame.memory_used_total_card.detail is None


# ==============================================================================
# 3. Snapshot Presentation and Metric Derivation
# ==============================================================================


def test_summary_cards_populate_actual_snapshot(qapp: QApplication) -> None:
    """All 4 metric cards display correct formatted values from snapshot."""
    snap = _make_snapshot(
        cpu_percent=18.4,
        memory_percent=55.2,
        disk_usage_percent=72.1,
        memory_used=8_589_934_592,  # 8.0 GiB
        memory_total=17_179_869_184,  # 16.0 GiB
    )
    frame = ResourcesSummaryCardsFrame()
    frame.set_snapshot(snap)

    assert frame.current_snapshot is snap
    assert frame.cpu_card.value == "18.4%"
    assert frame.memory_card.value == "55.2%"
    assert frame.disk_card.value == "72.1%"
    assert frame.memory_used_total_card.value == "8.0 GiB / 16.0 GiB"

    # All cards have the distinction detail "Latest snapshot"
    assert frame.cpu_card.detail == "Latest snapshot"
    assert frame.memory_card.detail == "Latest snapshot"
    assert frame.disk_card.detail == "Latest snapshot"
    assert frame.memory_used_total_card.detail == "Latest snapshot"


def test_summary_cards_preserve_numeric_zero(qapp: QApplication) -> None:
    """0.0% and 0 B metrics are preserved and not replaced by placeholders."""
    snap = _make_snapshot(
        cpu_percent=0.0,
        memory_percent=0.0,
        disk_usage_percent=0.0,
        memory_used=0,
        memory_total=1073741824,  # 1.0 GiB
    )
    frame = ResourcesSummaryCardsFrame()
    frame.set_snapshot(snap)

    assert frame.cpu_card.value == "0.0%"
    assert frame.memory_card.value == "0.0%"
    assert frame.disk_card.value == "0.0%"
    assert frame.memory_used_total_card.value == "0 B / 1.0 GiB"


def test_summary_cards_nullable_percentages(qapp: QApplication) -> None:
    """Nullable percentages are displayed as EMPTY_PLACEHOLDER ('—')."""
    snap = _make_snapshot(
        cpu_percent=None,
        memory_percent=None,
        disk_usage_percent=None,
    )
    frame = ResourcesSummaryCardsFrame()
    frame.set_snapshot(snap)

    assert frame.cpu_card.value == EMPTY_PLACEHOLDER
    assert frame.memory_card.value == EMPTY_PLACEHOLDER
    assert frame.disk_card.value == EMPTY_PLACEHOLDER


def test_summary_cards_memory_used_total_combinations(
    qapp: QApplication,
) -> None:
    """Memory used vs total handles all partial availability cases."""
    frame = ResourcesSummaryCardsFrame()

    # Case 1: Both present
    s1 = _make_snapshot(memory_used=1073741824, memory_total=2147483648)
    frame.set_snapshot(s1)
    assert frame.memory_used_total_card.value == "1.0 GiB / 2.0 GiB"

    # Case 2: Used present, Total None
    s2 = _make_snapshot(memory_used=1073741824, memory_total=None)
    frame.set_snapshot(s2)
    assert frame.memory_used_total_card.value == f"1.0 GiB / {EMPTY_PLACEHOLDER}"

    # Case 3: Used None, Total present
    s3 = _make_snapshot(memory_used=None, memory_total=2147483648)
    frame.set_snapshot(s3)
    assert frame.memory_used_total_card.value == f"{EMPTY_PLACEHOLDER} / 2.0 GiB"

    # Case 4: Neither present
    s4 = _make_snapshot(memory_used=None, memory_total=None)
    frame.set_snapshot(s4)
    assert frame.memory_used_total_card.value == EMPTY_PLACEHOLDER


# ==============================================================================
# 4. State Management and Collection Updates
# ==============================================================================


def test_summary_cards_set_none_and_clear(qapp: QApplication) -> None:
    """set_snapshot(None) and clear() reset all cards to neutral placeholders."""
    snap = _make_snapshot()
    frame = ResourcesSummaryCardsFrame()
    frame.set_snapshot(snap)
    assert frame.cpu_card.value == "20.0%"

    frame.clear()
    assert frame.current_snapshot is None
    assert frame.cpu_card.value == EMPTY_PLACEHOLDER
    assert frame.cpu_card.detail is None
    assert frame.memory_card.value == EMPTY_PLACEHOLDER
    assert frame.disk_card.value == EMPTY_PLACEHOLDER
    assert frame.memory_used_total_card.value == EMPTY_PLACEHOLDER


def test_summary_cards_update_from_collection(qapp: QApplication) -> None:
    """update_from_collection selects newest snapshot in unordered collection."""
    s_old = _make_snapshot(
        snapshot_id=SAMPLE_SNAPSHOT_ID_1,
        timestamp=TIME_EARLY,
        cpu_percent=10.0,
    )
    s_new = _make_snapshot(
        snapshot_id=SAMPLE_SNAPSHOT_ID_2,
        timestamp=TIME_LATE,
        cpu_percent=90.0,
    )

    # Reverse order
    col = ResourceSnapshotCollection(
        total=2,
        items=(s_new, s_old),
        limit=50,
        offset=0,
    )

    frame = ResourcesSummaryCardsFrame()
    frame.update_from_collection(col)

    assert frame.current_snapshot is s_new
    assert frame.cpu_card.value == "90.0%"


def test_summary_cards_update_from_empty_collection(
    qapp: QApplication,
) -> None:
    """Empty collection resets previous summaries to placeholders."""
    snap = _make_snapshot(cpu_percent=75.0)
    frame = ResourcesSummaryCardsFrame()
    frame.set_snapshot(snap)
    assert frame.cpu_card.value == "75.0%"

    empty_col = ResourceSnapshotCollection(
        total=0,
        items=(),
        limit=50,
        offset=0,
    )
    frame.update_from_collection(empty_col)
    assert frame.current_snapshot is None
    assert frame.cpu_card.value == EMPTY_PLACEHOLDER


def test_summary_cards_update_from_snapshots(qapp: QApplication) -> None:
    """update_from_snapshots handles sequences, None, and empty lists."""
    s1 = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_1, timestamp=TIME_EARLY)
    s2 = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_2, timestamp=TIME_LATE)

    frame = ResourcesSummaryCardsFrame()
    frame.update_from_snapshots([s1, s2])
    assert frame.current_snapshot is s2

    # None or empty resets
    frame.update_from_snapshots(None)
    assert frame.current_snapshot is None
    assert frame.cpu_card.value == EMPTY_PLACEHOLDER

    frame.update_from_snapshots([s1])
    assert frame.current_snapshot is s1
    frame.update_from_snapshots([])
    assert frame.current_snapshot is None

    # Clear alias
    frame.set_snapshot(s1)
    assert frame.current_snapshot is s1
    frame.clear()
    assert frame.current_snapshot is None


def test_summary_cards_has_no_backend_or_http_imports() -> None:
    """resources_summary_cards has no network or DB dependencies."""
    import desktop.ui.components.resources_summary_cards as mod

    for prohibited in (
        "httpx",
        "fastapi",
        "starlette",
        "sqlalchemy",
        "respx",
    ):
        assert not hasattr(mod, prohibited)

    for mod_name in sys.modules:
        if mod_name.startswith("desktop.ui.components.resources_summary_cards"):
            mod_obj = sys.modules[mod_name]
            for forbidden in ("httpx", "sqlalchemy"):
                assert forbidden not in mod_obj.__dict__
