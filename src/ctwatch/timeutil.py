"""UTC-only time helpers.

Every timestamp written to the database or to a report is UTC with an explicit
offset. Investigation notes get compared across time zones and across teams;
a naive local timestamp is a defect waiting to happen.
"""

from __future__ import annotations

from datetime import UTC, datetime


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
