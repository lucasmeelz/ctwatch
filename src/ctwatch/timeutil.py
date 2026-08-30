"""UTC-only time helpers.

Every timestamp written to the database or to a report is UTC with an explicit
offset. Investigation notes get compared across time zones and across teams;
a naive local timestamp is a defect waiting to happen.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta


def utc_now() -> datetime:
    return datetime.now(UTC)


def to_iso(moment: datetime) -> str:
    if moment.tzinfo is None:
        msg = "refusing to serialise a naive datetime; attach a timezone first"
        raise ValueError(msg)
    return moment.astimezone(UTC).isoformat()


def utc_now_iso() -> str:
    return to_iso(utc_now())


def parse_iso(value: str) -> datetime:
    """Parse an ISO-8601 timestamp, assuming UTC when no offset is present.

    Certificate Transparency sources are not consistent here: crt.sh returns
    naive strings that are in fact UTC, while others include an offset.
    """

    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


_DURATION_UNITS: dict[str, int] = {
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
    "w": 604800,
}


def parse_duration(value: str) -> timedelta:
    """Parse a short duration such as ``30d``, ``12h`` or ``90m``."""

    cleaned = value.strip().lower()
    if not cleaned:
        msg = "duration must not be empty"
        raise ValueError(msg)

    unit = cleaned[-1]
    if unit.isdigit():
        # A bare number is read as days, which is what `--since 30` means to
        # everyone who types it.
        unit, amount_text = "d", cleaned
    else:
        amount_text = cleaned[:-1]

    if unit not in _DURATION_UNITS:
        allowed = ", ".join(sorted(_DURATION_UNITS))
        msg = f"unknown duration unit {unit!r}; use one of: {allowed}"
        raise ValueError(msg)
    try:
        amount = float(amount_text)
    except ValueError as exc:
        msg = f"not a duration: {value!r} (expected something like 30d or 12h)"
        raise ValueError(msg) from exc
    if amount < 0:
        msg = f"duration must not be negative: {value!r}"
        raise ValueError(msg)
    return timedelta(seconds=amount * _DURATION_UNITS[unit])
