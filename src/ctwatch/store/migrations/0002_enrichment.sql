-- Passive enrichment.
--
-- Everything recorded here comes from a third party talking about the domain,
-- never from the domain itself: the registry (RDAP), a public resolver, and
-- urlscan.io. Each row points at the archived response it was read from, so a
-- registrar name or an IP address quoted in a report can be traced back to
-- bytes on disk.

CREATE TABLE registrations (
    id               INTEGER PRIMARY KEY,
    domain_id        INTEGER NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
    evidence_id      INTEGER NOT NULL REFERENCES evidence (id),
    rdap_server      TEXT,
    registrar        TEXT,
    registered_at    TEXT,
    expires_at       TEXT,
    last_changed_at  TEXT,
    statuses         TEXT NOT NULL DEFAULT '[]',
    nameservers      TEXT NOT NULL DEFAULT '[]',
    retrieved_at     TEXT NOT NULL,
    UNIQUE (domain_id)
);

CREATE INDEX idx_registrations_registrar ON registrations (registrar);
CREATE INDEX idx_registrations_registered_at ON registrations (registered_at);

CREATE TABLE dns_records (
    id           INTEGER PRIMARY KEY,
    domain_id    INTEGER NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
    evidence_id  INTEGER NOT NULL REFERENCES evidence (id),
    record_type  TEXT    NOT NULL,
    value        TEXT    NOT NULL,
    ttl          INTEGER,
    observed_at  TEXT    NOT NULL,
    UNIQUE (domain_id, record_type, value)
);

CREATE INDEX idx_dns_records_value ON dns_records (record_type, value);

CREATE TABLE url_scans (
    id             INTEGER PRIMARY KEY,
    domain_id      INTEGER NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
    evidence_id    INTEGER NOT NULL REFERENCES evidence (id),
    scan_uuid      TEXT,
    result_url     TEXT,
    screenshot_url TEXT,
    page_ip        TEXT,
    page_asn       TEXT,
    page_asn_name  TEXT,
    page_server    TEXT,
    page_title     TEXT,
    scanned_at     TEXT,
    retrieved_at   TEXT NOT NULL,
    UNIQUE (domain_id, scan_uuid)
);

CREATE INDEX idx_url_scans_asn ON url_scans (page_asn);
CREATE INDEX idx_url_scans_ip ON url_scans (page_ip);
