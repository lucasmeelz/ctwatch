"""Data access layer.

Thin, explicit SQL rather than an ORM: the queries here are read by people who
need to trust what the tool claims, and an opaque query builder would work
against that.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any

from ctwatch.store.models import (
    CertificateRecord,
    DomainRecord,
    EvidenceRecord,
    ObservationRecord,
    WatchTarget,
)
from ctwatch.timeutil import parse_iso, to_iso, utc_now


def _text(row: sqlite3.Row, key: str) -> str:
    value = row[key]
    return str(value)


def _optional_text(row: sqlite3.Row, key: str) -> str | None:
    value = row[key]
    return None if value is None else str(value)


def _moment(row: sqlite3.Row, key: str) -> datetime | None:
    value = row[key]
    return None if value is None else parse_iso(str(value))


def _json_list(row: sqlite3.Row, key: str) -> tuple[str, ...]:
    raw = row[key]
    if not raw:
        return ()
    decoded: Any = json.loads(str(raw))
    if not isinstance(decoded, list):
        return ()
    return tuple(str(item) for item in decoded)


def _watch_target(row: sqlite3.Row) -> WatchTarget:
    return WatchTarget(
        id=int(row["id"]),
        brand=_text(row, "brand"),
        canonical_domain=_text(row, "canonical_domain"),
        keywords=_json_list(row, "keywords"),
        allowlist=_json_list(row, "allowlist"),
        active=bool(row["active"]),
        created_at=_moment(row, "created_at"),
    )


def _evidence(row: sqlite3.Row) -> EvidenceRecord:
    requested_at = _moment(row, "requested_at")
    if requested_at is None:  # pragma: no cover - column is NOT NULL
        msg = "evidence row is missing its retrieval timestamp"
        raise ValueError(msg)
    meta_raw: Any = json.loads(_text(row, "meta") or "{}")
    return EvidenceRecord(
        id=int(row["id"]),
        source=_text(row, "source"),
        endpoint=_text(row, "endpoint"),
        requested_at=requested_at,
        status_code=None if row["status_code"] is None else int(row["status_code"]),
        content_sha256=_text(row, "content_sha256"),
        content_length=int(row["content_length"]),
        blob_path=_text(row, "blob_path"),
        meta=meta_raw if isinstance(meta_raw, dict) else {},
    )


def _domain(row: sqlite3.Row) -> DomainRecord:
    return DomainRecord(
        id=int(row["id"]),
        name=_text(row, "name"),
        unicode_name=_optional_text(row, "unicode_name"),
        registrable_domain=_optional_text(row, "registrable_domain"),
        tld=_optional_text(row, "tld"),
        is_wildcard=bool(row["is_wildcard"]),
        is_idn=bool(row["is_idn"]),
        first_seen_at=_moment(row, "first_seen_at"),
        last_seen_at=_moment(row, "last_seen_at"),
    )


def _certificate(row: sqlite3.Row) -> CertificateRecord:
    return CertificateRecord(
        id=int(row["id"]),
        source=_text(row, "source"),
        fingerprint_sha256=_optional_text(row, "fingerprint_sha256"),
        source_ref=_optional_text(row, "source_ref"),
        issuer=_optional_text(row, "issuer"),
        serial_number=_optional_text(row, "serial_number"),
        not_before=_moment(row, "not_before"),
        not_after=_moment(row, "not_after"),
        entry_timestamp=_moment(row, "entry_timestamp"),
        first_seen_at=_moment(row, "first_seen_at"),
    )


class Repository:
    """All reads and writes go through here."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    @property
    def connection(self) -> sqlite3.Connection:
        return self._connection

    # ------------------------------------------------------------------
    # Watch targets

    def upsert_target(
        self,
        *,
        brand: str,
        canonical_domain: str,
        keywords: list[str] | tuple[str, ...] = (),
        allowlist: list[str] | tuple[str, ...] = (),
    ) -> WatchTarget:
        """Add a target, or update the brand and lists of an existing one."""

        normalized = canonical_domain.strip().lower().rstrip(".")
        if not normalized:
            msg = "canonical domain must not be empty"
            raise ValueError(msg)

        self._connection.execute(
            """
            INSERT INTO watch_targets (brand, canonical_domain, keywords, allowlist, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (canonical_domain) DO UPDATE SET
                brand = excluded.brand,
                keywords = excluded.keywords,
                allowlist = excluded.allowlist,
                active = 1
            """,
            (
                brand.strip(),
                normalized,
                json.dumps(sorted({k.strip().lower() for k in keywords if k.strip()})),
                json.dumps(sorted({a.strip().lower() for a in allowlist if a.strip()})),
                to_iso(utc_now()),
            ),
        )
        target = self.get_target(normalized)
        if target is None:  # pragma: no cover - the insert above guarantees it
            msg = f"target {normalized!r} vanished right after being written"
            raise RuntimeError(msg)
        return target

    def get_target(self, canonical_domain: str) -> WatchTarget | None:
        row = self._connection.execute(
            "SELECT * FROM watch_targets WHERE canonical_domain = ?",
            (canonical_domain.strip().lower().rstrip("."),),
        ).fetchone()
        return None if row is None else _watch_target(row)

    def get_target_by_id(self, target_id: int) -> WatchTarget | None:
        row = self._connection.execute(
            "SELECT * FROM watch_targets WHERE id = ?", (target_id,)
        ).fetchone()
        return None if row is None else _watch_target(row)

    def list_targets(self, *, active_only: bool = True) -> list[WatchTarget]:
        query = "SELECT * FROM watch_targets"
        if active_only:
            query += " WHERE active = 1"
        query += " ORDER BY brand COLLATE NOCASE, canonical_domain"
        return [_watch_target(row) for row in self._connection.execute(query)]

    def deactivate_target(self, canonical_domain: str) -> bool:
        cursor = self._connection.execute(
            "UPDATE watch_targets SET active = 0 WHERE canonical_domain = ? AND active = 1",
            (canonical_domain.strip().lower().rstrip("."),),
        )
        return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Evidence

    def insert_evidence(
        self,
        *,
        source: str,
        endpoint: str,
        requested_at: datetime,
        status_code: int | None,
        content_sha256: str,
        content_length: int,
        blob_path: str,
        meta: dict[str, Any] | None = None,
    ) -> EvidenceRecord:
        cursor = self._connection.execute(
            """
            INSERT INTO evidence (
                source, endpoint, requested_at, status_code,
                content_sha256, content_length, blob_path, meta
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source,
                endpoint,
                to_iso(requested_at),
                status_code,
                content_sha256,
                content_length,
                blob_path,
                json.dumps(meta or {}, sort_keys=True),
            ),
        )
        evidence_id = cursor.lastrowid
        if evidence_id is None:  # pragma: no cover - sqlite always sets it here
            msg = "evidence row was not assigned an id"
            raise RuntimeError(msg)
        record = self.get_evidence(int(evidence_id))
        if record is None:  # pragma: no cover
            msg = "evidence row vanished right after being written"
            raise RuntimeError(msg)
        return record

    def get_evidence(self, evidence_id: int) -> EvidenceRecord | None:
        row = self._connection.execute(
            "SELECT * FROM evidence WHERE id = ?", (evidence_id,)
        ).fetchone()
        return None if row is None else _evidence(row)

    # ------------------------------------------------------------------
    # Domains

    def upsert_domain(
        self,
        *,
        name: str,
        unicode_name: str | None = None,
        registrable_domain: str | None = None,
        tld: str | None = None,
        is_wildcard: bool = False,
        is_idn: bool = False,
        seen_at: datetime | None = None,
    ) -> DomainRecord:
        moment = to_iso(seen_at or utc_now())
        self._connection.execute(
            """
            INSERT INTO domains (
                name, unicode_name, registrable_domain, tld,
                is_wildcard, is_idn, first_seen_at, last_seen_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (name) DO UPDATE SET
                unicode_name = COALESCE(excluded.unicode_name, domains.unicode_name),
                registrable_domain =
                    COALESCE(excluded.registrable_domain, domains.registrable_domain),
                tld = COALESCE(excluded.tld, domains.tld),
                is_idn = MAX(domains.is_idn, excluded.is_idn),
                is_wildcard = MAX(domains.is_wildcard, excluded.is_wildcard),
                first_seen_at = MIN(domains.first_seen_at, excluded.first_seen_at),
                last_seen_at = MAX(domains.last_seen_at, excluded.last_seen_at)
            """,
            (
                name,
                unicode_name,
                registrable_domain,
                tld,
                int(is_wildcard),
                int(is_idn),
                moment,
                moment,
            ),
        )
        record = self.get_domain(name)
        if record is None:  # pragma: no cover
            msg = f"domain {name!r} vanished right after being written"
            raise RuntimeError(msg)
        return record

    def get_domain(self, name: str) -> DomainRecord | None:
        row = self._connection.execute("SELECT * FROM domains WHERE name = ?", (name,)).fetchone()
        return None if row is None else _domain(row)

    def count_domains(self) -> int:
        row = self._connection.execute("SELECT COUNT(*) AS total FROM domains").fetchone()
        return int(row["total"])

    # ------------------------------------------------------------------
    # Certificates

    def upsert_certificate(
        self,
        *,
        source: str,
        fingerprint_sha256: str | None = None,
        source_ref: str | None = None,
        issuer: str | None = None,
        serial_number: str | None = None,
        not_before: datetime | None = None,
        not_after: datetime | None = None,
        entry_timestamp: datetime | None = None,
    ) -> CertificateRecord:
        """Insert a certificate, reconciling with one already seen.

        Identity is the fingerprint when a source provides one, and the
        (source, source reference) pair otherwise. crt.sh does not return a
        fingerprint in its JSON listing, which is why both paths exist.
        """

        existing = self.find_certificate(
            source=source, fingerprint_sha256=fingerprint_sha256, source_ref=source_ref
        )
        values = (
            fingerprint_sha256,
            issuer,
            serial_number,
            None if not_before is None else to_iso(not_before),
            None if not_after is None else to_iso(not_after),
            None if entry_timestamp is None else to_iso(entry_timestamp),
        )

        if existing is not None:
            self._connection.execute(
                """
                UPDATE certificates SET
                    fingerprint_sha256 = COALESCE(?, fingerprint_sha256),
                    issuer = COALESCE(?, issuer),
                    serial_number = COALESCE(?, serial_number),
                    not_before = COALESCE(?, not_before),
                    not_after = COALESCE(?, not_after),
                    entry_timestamp = COALESCE(?, entry_timestamp)
                WHERE id = ?
                """,
                (*values, existing.id),
            )
            refreshed = self.get_certificate(existing.id)
            if refreshed is None:  # pragma: no cover
                msg = "certificate vanished right after being updated"
                raise RuntimeError(msg)
            return refreshed

        cursor = self._connection.execute(
            """
            INSERT INTO certificates (
                fingerprint_sha256, source, source_ref, issuer, serial_number,
                not_before, not_after, entry_timestamp, first_seen_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                fingerprint_sha256,
                source,
                source_ref,
                issuer,
                serial_number,
                values[3],
                values[4],
                values[5],
                to_iso(utc_now()),
            ),
        )
        certificate_id = cursor.lastrowid
        if certificate_id is None:  # pragma: no cover
            msg = "certificate row was not assigned an id"
            raise RuntimeError(msg)
        record = self.get_certificate(int(certificate_id))
        if record is None:  # pragma: no cover
            msg = "certificate vanished right after being written"
            raise RuntimeError(msg)
        return record

    def find_certificate(
        self,
        *,
        source: str,
        fingerprint_sha256: str | None = None,
        source_ref: str | None = None,
    ) -> CertificateRecord | None:
        if fingerprint_sha256:
            row = self._connection.execute(
                "SELECT * FROM certificates WHERE fingerprint_sha256 = ?",
                (fingerprint_sha256,),
            ).fetchone()
            if row is not None:
                return _certificate(row)
        if source_ref:
            row = self._connection.execute(
                "SELECT * FROM certificates WHERE source = ? AND source_ref = ?",
                (source, source_ref),
            ).fetchone()
            if row is not None:
                return _certificate(row)
        return None

    def get_certificate(self, certificate_id: int) -> CertificateRecord | None:
        row = self._connection.execute(
            "SELECT * FROM certificates WHERE id = ?", (certificate_id,)
        ).fetchone()
        return None if row is None else _certificate(row)

    # ------------------------------------------------------------------
    # Observations

    def record_observation(
        self,
        *,
        domain_id: int,
        evidence_id: int,
        source: str,
        observed_at: datetime | None = None,
        certificate_id: int | None = None,
        target_id: int | None = None,
        query: str | None = None,
    ) -> ObservationRecord | None:
        """Link a domain to the evidence it was seen in.

        Returns ``None`` when the exact same observation was already recorded,
        which happens whenever a cached response is replayed.
        """

        moment = observed_at or utc_now()
        cursor = self._connection.execute(
            """
            INSERT OR IGNORE INTO observations (
                domain_id, certificate_id, target_id, evidence_id, source, query, observed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (domain_id, certificate_id, target_id, evidence_id, source, query, to_iso(moment)),
        )
        if cursor.rowcount == 0:
            return None
        observation_id = cursor.lastrowid
        if observation_id is None:  # pragma: no cover
            msg = "observation row was not assigned an id"
            raise RuntimeError(msg)
        return ObservationRecord(
            id=int(observation_id),
            domain_id=domain_id,
            evidence_id=evidence_id,
            source=source,
            observed_at=moment,
            certificate_id=certificate_id,
            target_id=target_id,
            query=query,
        )

    def names_sharing_certificate(self, domain_id: int) -> list[str]:
        """Every domain name seen on a certificate this domain also appears on.

        The cheapest ownership signal available: a certificate is issued to
        someone who proved control of every name on it.
        """

        rows = self._connection.execute(
            """
            SELECT DISTINCT other_domain.name AS name
            FROM observations AS mine
            JOIN observations AS theirs
                ON theirs.certificate_id = mine.certificate_id
            JOIN domains AS other_domain
                ON other_domain.id = theirs.domain_id
            WHERE mine.domain_id = ?
              AND mine.certificate_id IS NOT NULL
            ORDER BY other_domain.name
            """,
            (domain_id,),
        ).fetchall()
        return [_text(row, "name") for row in rows]

    def count_observations(self, *, target_id: int | None = None) -> int:
        if target_id is None:
            row = self._connection.execute("SELECT COUNT(*) AS total FROM observations").fetchone()
        else:
            row = self._connection.execute(
                "SELECT COUNT(*) AS total FROM observations WHERE target_id = ?", (target_id,)
            ).fetchone()
        return int(row["total"])

    # ------------------------------------------------------------------
    # Findings

    def domains_for_target(self, target_id: int) -> list[DomainRecord]:
        """Every domain observed while scanning this target."""

        rows = self._connection.execute(
            """
            SELECT DISTINCT domains.* FROM domains
            JOIN observations ON observations.domain_id = domains.id
            WHERE observations.target_id = ?
            ORDER BY domains.name
            """,
            (target_id,),
        ).fetchall()
        return [_domain(row) for row in rows]

    def newest_certificate_for_domain(self, domain_id: int) -> CertificateRecord | None:
        """The most recently issued certificate covering this domain.

        Recency is the point: an operation being set up now is what matters,
        and an old certificate on the same name says little about it.
        """

        row = self._connection.execute(
            """
            SELECT certificates.* FROM certificates
            JOIN observations ON observations.certificate_id = certificates.id
            WHERE observations.domain_id = ?
            ORDER BY COALESCE(certificates.not_before, certificates.entry_timestamp) DESC
            LIMIT 1
            """,
            (domain_id,),
        ).fetchone()
        return None if row is None else _certificate(row)

    def evidence_ids_for_domain(self, domain_id: int) -> list[int]:
        rows = self._connection.execute(
            "SELECT DISTINCT evidence_id FROM observations "
            "WHERE domain_id = ? ORDER BY evidence_id",
            (domain_id,),
        ).fetchall()
        return [int(row["evidence_id"]) for row in rows]

    def evidence_for_domain(self, domain_id: int) -> list[EvidenceRecord]:
        """Every archived response that says anything about this domain.

        Not only the certificate listings it was seen in: a report that cites a
        registrar has to be able to hand over the RDAP response it read that
        from, and the same goes for resolution and page rendering.
        """

        rows = self._connection.execute(
            """
            SELECT evidence.* FROM evidence
            WHERE evidence.id IN (
                SELECT evidence_id FROM observations WHERE domain_id = :domain
                UNION
                SELECT evidence_id FROM registrations WHERE domain_id = :domain
                UNION
                SELECT evidence_id FROM dns_records WHERE domain_id = :domain
                UNION
                SELECT evidence_id FROM url_scans WHERE domain_id = :domain
            )
            ORDER BY evidence.requested_at, evidence.id
            """,
            {"domain": domain_id},
        ).fetchall()
        return [_evidence(row) for row in rows]

    def certificates_for_domain(self, domain_id: int) -> list[CertificateRecord]:
        rows = self._connection.execute(
            """
            SELECT DISTINCT certificates.* FROM certificates
            JOIN observations ON observations.certificate_id = certificates.id
            WHERE observations.domain_id = ?
            ORDER BY COALESCE(certificates.not_before, certificates.entry_timestamp) DESC
            """,
            (domain_id,),
        ).fetchall()
        return [_certificate(row) for row in rows]

    def observations_for_domain(self, domain_id: int) -> list[sqlite3.Row]:
        return list(
            self._connection.execute(
                """
                SELECT observations.*, evidence.endpoint AS endpoint,
                       evidence.content_sha256 AS content_sha256
                FROM observations
                JOIN evidence ON evidence.id = observations.evidence_id
                WHERE observations.domain_id = ?
                ORDER BY observations.observed_at
                """,
                (domain_id,),
            )
        )

    def upsert_finding(
        self,
        *,
        target_id: int,
        domain_id: int,
        score: float,
        breakdown: dict[str, Any],
        confidence: str | None = None,
        status: str = "new",
        notes: str | None = None,
    ) -> int:
        """Record an assessment, preserving a status a human has already set."""

        moment = to_iso(utc_now())
        self._connection.execute(
            """
            INSERT INTO findings (
                target_id, domain_id, score, breakdown, confidence, status, notes,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (target_id, domain_id) DO UPDATE SET
                score = excluded.score,
                breakdown = excluded.breakdown,
                confidence = excluded.confidence,
                -- A note a person wrote survives a rescan that has none.
                notes = COALESCE(excluded.notes, findings.notes),
                updated_at = excluded.updated_at,
                -- A verdict a person recorded is not overwritten by a rescan.
                status = CASE
                    WHEN findings.status IN ('reviewing', 'confirmed', 'dismissed')
                        THEN findings.status
                    ELSE excluded.status
                END
            """,
            (
                target_id,
                domain_id,
                score,
                json.dumps(breakdown, sort_keys=True),
                confidence,
                status,
                notes,
                moment,
                moment,
            ),
        )
        row = self._connection.execute(
            "SELECT id FROM findings WHERE target_id = ? AND domain_id = ?",
            (target_id, domain_id),
        ).fetchone()
        if row is None:  # pragma: no cover
            msg = "finding vanished right after being written"
            raise RuntimeError(msg)
        return int(row["id"])

    def list_findings(
        self,
        *,
        target_id: int | None = None,
        min_score: float = 0.0,
        include_allowlisted: bool = False,
        statuses: list[str] | None = None,
        limit: int | None = None,
    ) -> list[sqlite3.Row]:
        """Findings joined to the names and brands a report needs to show."""

        clauses = ["findings.score >= ?"]
        params: list[Any] = [min_score]

        if target_id is not None:
            clauses.append("findings.target_id = ?")
            params.append(target_id)
        if not include_allowlisted:
            clauses.append("findings.status != 'allowlisted'")
        if statuses:
            placeholders = ", ".join("?" for _ in statuses)
            clauses.append(f"findings.status IN ({placeholders})")
            params.extend(statuses)

        query = f"""
            SELECT
                findings.*,
                domains.name AS domain_name,
                domains.unicode_name AS domain_unicode_name,
                domains.is_idn AS domain_is_idn,
                watch_targets.brand AS brand,
                watch_targets.canonical_domain AS canonical_domain
            FROM findings
            JOIN domains ON domains.id = findings.domain_id
            JOIN watch_targets ON watch_targets.id = findings.target_id
            WHERE {" AND ".join(clauses)}
            ORDER BY findings.score DESC, domains.name
        """
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)

        return list(self._connection.execute(query, params))

    def get_finding(self, finding_id: int) -> sqlite3.Row | None:
        row: sqlite3.Row | None = self._connection.execute(
            """
            SELECT findings.*, domains.name AS domain_name
            FROM findings
            JOIN domains ON domains.id = findings.domain_id
            WHERE findings.id = ?
            """,
            (finding_id,),
        ).fetchone()
        return row

    def get_domain_by_id(self, domain_id: int) -> DomainRecord | None:
        row = self._connection.execute(
            "SELECT * FROM domains WHERE id = ?", (domain_id,)
        ).fetchone()
        return None if row is None else _domain(row)

    def domains_for_findings(
        self, *, target_id: int | None = None, min_score: float = 0.0, limit: int | None = None
    ) -> list[DomainRecord]:
        """Domains worth enriching: reported findings, highest score first."""

        clauses = ["findings.score >= ?", "findings.status != 'allowlisted'"]
        params: list[Any] = [min_score]
        if target_id is not None:
            clauses.append("findings.target_id = ?")
            params.append(target_id)

        query = f"""
            SELECT domains.* FROM findings
            JOIN domains ON domains.id = findings.domain_id
            WHERE {" AND ".join(clauses)}
            ORDER BY findings.score DESC, domains.name
        """
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
        return [_domain(row) for row in self._connection.execute(query, params)]

    def count_findings(self, *, target_id: int | None = None) -> int:
        if target_id is None:
            row = self._connection.execute("SELECT COUNT(*) AS total FROM findings").fetchone()
        else:
            row = self._connection.execute(
                "SELECT COUNT(*) AS total FROM findings WHERE target_id = ?", (target_id,)
            ).fetchone()
        return int(row["total"])

    def set_finding_status(self, finding_id: int, status: str, *, notes: str | None = None) -> bool:
        cursor = self._connection.execute(
            "UPDATE findings SET status = ?, notes = COALESCE(?, notes), updated_at = ? "
            "WHERE id = ?",
            (status, notes, to_iso(utc_now()), finding_id),
        )
        return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Enrichment

    def upsert_registration(
        self,
        *,
        domain_id: int,
        evidence_id: int,
        rdap_server: str | None,
        registrar: str | None,
        registered_at: datetime | None,
        expires_at: datetime | None,
        last_changed_at: datetime | None,
        statuses: list[str] | tuple[str, ...] = (),
        nameservers: list[str] | tuple[str, ...] = (),
        retrieved_at: datetime | None = None,
    ) -> None:
        self._connection.execute(
            """
            INSERT INTO registrations (
                domain_id, evidence_id, rdap_server, registrar, registered_at,
                expires_at, last_changed_at, statuses, nameservers, retrieved_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (domain_id) DO UPDATE SET
                evidence_id = excluded.evidence_id,
                rdap_server = excluded.rdap_server,
                registrar = excluded.registrar,
                registered_at = excluded.registered_at,
                expires_at = excluded.expires_at,
                last_changed_at = excluded.last_changed_at,
                statuses = excluded.statuses,
                nameservers = excluded.nameservers,
                retrieved_at = excluded.retrieved_at
            """,
            (
                domain_id,
                evidence_id,
                rdap_server,
                registrar,
                None if registered_at is None else to_iso(registered_at),
                None if expires_at is None else to_iso(expires_at),
                None if last_changed_at is None else to_iso(last_changed_at),
                json.dumps(list(statuses)),
                json.dumps(list(nameservers)),
                to_iso(retrieved_at or utc_now()),
            ),
        )

    def get_registration(self, domain_id: int) -> sqlite3.Row | None:
        row: sqlite3.Row | None = self._connection.execute(
            "SELECT * FROM registrations WHERE domain_id = ?", (domain_id,)
        ).fetchone()
        return row

    def record_dns_record(
        self,
        *,
        domain_id: int,
        evidence_id: int,
        record_type: str,
        value: str,
        ttl: int | None = None,
        observed_at: datetime | None = None,
    ) -> None:
        self._connection.execute(
            """
            INSERT INTO dns_records (
                domain_id, evidence_id, record_type, value, ttl, observed_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (domain_id, record_type, value) DO UPDATE SET
                evidence_id = excluded.evidence_id,
                ttl = excluded.ttl,
                observed_at = excluded.observed_at
            """,
            (
                domain_id,
                evidence_id,
                record_type,
                value,
                ttl,
                to_iso(observed_at or utc_now()),
            ),
        )

    def dns_records_for(self, domain_id: int) -> list[sqlite3.Row]:
        return list(
            self._connection.execute(
                "SELECT * FROM dns_records WHERE domain_id = ? ORDER BY record_type, value",
                (domain_id,),
            )
        )

    def upsert_url_scan(
        self,
        *,
        domain_id: int,
        evidence_id: int,
        scan_uuid: str | None,
        result_url: str | None = None,
        screenshot_url: str | None = None,
        page_ip: str | None = None,
        page_asn: str | None = None,
        page_asn_name: str | None = None,
        page_server: str | None = None,
        page_title: str | None = None,
        scanned_at: datetime | None = None,
        retrieved_at: datetime | None = None,
    ) -> None:
        self._connection.execute(
            """
            INSERT INTO url_scans (
                domain_id, evidence_id, scan_uuid, result_url, screenshot_url,
                page_ip, page_asn, page_asn_name, page_server, page_title,
                scanned_at, retrieved_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (domain_id, scan_uuid) DO UPDATE SET
                evidence_id = excluded.evidence_id,
                result_url = excluded.result_url,
                screenshot_url = excluded.screenshot_url,
                page_ip = excluded.page_ip,
                page_asn = excluded.page_asn,
                page_asn_name = excluded.page_asn_name,
                page_server = excluded.page_server,
                page_title = excluded.page_title,
                scanned_at = excluded.scanned_at,
                retrieved_at = excluded.retrieved_at
            """,
            (
                domain_id,
                evidence_id,
                scan_uuid,
                result_url,
                screenshot_url,
                page_ip,
                page_asn,
                page_asn_name,
                page_server,
                page_title,
                None if scanned_at is None else to_iso(scanned_at),
                to_iso(retrieved_at or utc_now()),
            ),
        )

    def url_scans_for(self, domain_id: int) -> list[sqlite3.Row]:
        return list(
            self._connection.execute(
                "SELECT * FROM url_scans WHERE domain_id = ? ORDER BY scanned_at DESC",
                (domain_id,),
            )
        )

    # ------------------------------------------------------------------
    # Pivots

    def domains_sharing_dns_value(self, record_type: str, value: str) -> list[str]:
        """Every domain resolving to the same address, nameserver or exchange."""

        rows = self._connection.execute(
            """
            SELECT DISTINCT domains.name AS name FROM dns_records
            JOIN domains ON domains.id = dns_records.domain_id
            WHERE dns_records.record_type = ? AND dns_records.value = ?
            ORDER BY domains.name
            """,
            (record_type, value),
        ).fetchall()
        return [_text(row, "name") for row in rows]

    def domains_sharing_asn(self, asn: str) -> list[str]:
        rows = self._connection.execute(
            """
            SELECT DISTINCT domains.name AS name FROM url_scans
            JOIN domains ON domains.id = url_scans.domain_id
            WHERE url_scans.page_asn = ?
            ORDER BY domains.name
            """,
            (asn,),
        ).fetchall()
        return [_text(row, "name") for row in rows]

    def domains_sharing_registrar(self, registrar: str) -> list[str]:
        rows = self._connection.execute(
            """
            SELECT DISTINCT domains.name AS name FROM registrations
            JOIN domains ON domains.id = registrations.domain_id
            WHERE registrations.registrar = ?
            ORDER BY domains.name
            """,
            (registrar,),
        ).fetchall()
        return [_text(row, "name") for row in rows]

    # ------------------------------------------------------------------
    # Source cache

    def cached_evidence(self, *, source: str, cache_key: str) -> EvidenceRecord | None:
        """Return a still-valid cached response, if any."""

        row = self._connection.execute(
            """
            SELECT evidence.* FROM source_cache
            JOIN evidence ON evidence.id = source_cache.evidence_id
            WHERE source_cache.source = ?
              AND source_cache.cache_key = ?
              AND source_cache.expires_at > ?
            """,
            (source, cache_key, to_iso(utc_now())),
        ).fetchone()
        return None if row is None else _evidence(row)

    def store_cache_entry(
        self,
        *,
        source: str,
        cache_key: str,
        evidence_id: int,
        expires_at: datetime,
        fetched_at: datetime | None = None,
    ) -> None:
        self._connection.execute(
            """
            INSERT INTO source_cache (source, cache_key, evidence_id, fetched_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (source, cache_key) DO UPDATE SET
                evidence_id = excluded.evidence_id,
                fetched_at = excluded.fetched_at,
                expires_at = excluded.expires_at
            """,
            (source, cache_key, evidence_id, to_iso(fetched_at or utc_now()), to_iso(expires_at)),
        )

    def purge_expired_cache(self) -> int:
        cursor = self._connection.execute(
            "DELETE FROM source_cache WHERE expires_at <= ?", (to_iso(utc_now()),)
        )
        return cursor.rowcount
