-- Initial schema.
--
-- Timestamps are stored as ISO-8601 strings in UTC, always with an explicit
-- offset, so that a database opened on another machine cannot be misread.
-- Anything that could later be quoted in a report is tied to an `evidence`
-- row, which points at the archived raw response it came from.

CREATE TABLE watch_targets (
    id                INTEGER PRIMARY KEY,
    brand             TEXT    NOT NULL,
    canonical_domain  TEXT    NOT NULL,
    keywords          TEXT    NOT NULL DEFAULT '[]',
    allowlist         TEXT    NOT NULL DEFAULT '[]',
    active            INTEGER NOT NULL DEFAULT 1,
    created_at        TEXT    NOT NULL,
    UNIQUE (canonical_domain)
);

CREATE INDEX idx_watch_targets_brand ON watch_targets (brand);

-- One row per raw response retrieved from an external service. `blob_path` is
-- relative to the configured evidence directory; the file is the gzipped body
-- exactly as received, and `content_sha256` is the digest of the uncompressed
-- bytes so a third party can verify it without our tooling.
CREATE TABLE evidence (
    id               INTEGER PRIMARY KEY,
    source           TEXT    NOT NULL,
    endpoint         TEXT    NOT NULL,
    requested_at     TEXT    NOT NULL,
    status_code      INTEGER,
    content_sha256   TEXT    NOT NULL,
    content_length   INTEGER NOT NULL,
    blob_path        TEXT    NOT NULL,
    meta             TEXT    NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_evidence_sha256 ON evidence (content_sha256);
CREATE INDEX idx_evidence_requested_at ON evidence (requested_at);

CREATE TABLE certificates (
    id                  INTEGER PRIMARY KEY,
    fingerprint_sha256  TEXT,
    source              TEXT    NOT NULL,
    source_ref          TEXT,
    issuer              TEXT,
    serial_number       TEXT,
    not_before          TEXT,
    not_after           TEXT,
    entry_timestamp     TEXT,
    first_seen_at       TEXT    NOT NULL
);

-- crt.sh does not return a fingerprint in its JSON listing, so identity falls
-- back to the pair (source, source_ref). Certificates seen through several
-- sources are reconciled on the fingerprint when at least one provides it.
CREATE UNIQUE INDEX idx_certificates_fingerprint
    ON certificates (fingerprint_sha256) WHERE fingerprint_sha256 IS NOT NULL;
CREATE UNIQUE INDEX idx_certificates_source_ref
    ON certificates (source, source_ref) WHERE source_ref IS NOT NULL;

-- `name` is always the ASCII (A-label) form, lowercased. `unicode_name` holds
-- the human-readable form when the domain is internationalised; it is what a
-- reader of the report actually sees in a browser.
CREATE TABLE domains (
    id                   INTEGER PRIMARY KEY,
    name                 TEXT    NOT NULL,
    unicode_name         TEXT,
    registrable_domain   TEXT,
    tld                  TEXT,
    is_wildcard          INTEGER NOT NULL DEFAULT 0,
    is_idn               INTEGER NOT NULL DEFAULT 0,
    first_seen_at        TEXT    NOT NULL,
    last_seen_at         TEXT    NOT NULL,
    UNIQUE (name)
);

CREATE INDEX idx_domains_registrable ON domains (registrable_domain);

CREATE TABLE observations (
    id              INTEGER PRIMARY KEY,
    domain_id       INTEGER NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
    certificate_id  INTEGER REFERENCES certificates (id) ON DELETE SET NULL,
    target_id       INTEGER REFERENCES watch_targets (id) ON DELETE SET NULL,
    evidence_id     INTEGER NOT NULL REFERENCES evidence (id),
    source          TEXT    NOT NULL,
    query           TEXT,
    observed_at     TEXT    NOT NULL
);

CREATE INDEX idx_observations_domain ON observations (domain_id);
CREATE INDEX idx_observations_target ON observations (target_id);
CREATE UNIQUE INDEX idx_observations_unique
    ON observations (domain_id, certificate_id, evidence_id);

CREATE TABLE findings (
    id          INTEGER PRIMARY KEY,
    target_id   INTEGER NOT NULL REFERENCES watch_targets (id) ON DELETE CASCADE,
    domain_id   INTEGER NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
    score       REAL    NOT NULL DEFAULT 0.0,
    breakdown   TEXT    NOT NULL DEFAULT '{}',
    confidence  TEXT,
    status      TEXT    NOT NULL DEFAULT 'new',
    notes       TEXT,
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL,
    UNIQUE (target_id, domain_id)
);

CREATE INDEX idx_findings_score ON findings (score DESC);
CREATE INDEX idx_findings_status ON findings (status);

-- Cache of source responses, keyed by the query that produced them. crt.sh is
-- slow and frequently unavailable; re-running a scan should not mean querying
-- it again for something we retrieved minutes ago.
CREATE TABLE source_cache (
    id           INTEGER PRIMARY KEY,
    source       TEXT    NOT NULL,
    cache_key    TEXT    NOT NULL,
    evidence_id  INTEGER NOT NULL REFERENCES evidence (id) ON DELETE CASCADE,
    fetched_at   TEXT    NOT NULL,
    expires_at   TEXT    NOT NULL,
    UNIQUE (source, cache_key)
);

CREATE INDEX idx_source_cache_expiry ON source_cache (expires_at);
