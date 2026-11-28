-- Superseded content rows a year of sweeps leaves in observation_sections and that the simulation above does not write:
--   * general: `jamfBinaryVersion` is hashed in the general section (docs/jamf-observations.md section 5), so each Jamf
--     upgrade writes one new general row per Mac. Twelve releases a year -> 480,000 rows, at the fixture's (small) body size.
--   * extension_attributes: one new row whenever any of a Mac's ~150 answers moves. At 10% of the fleet per day for a
--     year -> 1,460,000 rows. Their 150-digest arrays are TOASTed in a real ledger; written here with an empty array so
--     only the main-heap row (what a sequential scan reads) exists.
-- Content rows only; no spans are added for them (the queries reach current spans through the partial unique index).
\set ON_ERROR_STOP 1
SELECT set_config('looninspect.tenant_id', :'tenant', false);
INSERT INTO observation_sections (tenant_id, digest, section, body, entry_digests, entry_count, first_seen_at)
SELECT :'tenant', vdg('general-hist', i || ':' || k), 'general',
       jsonb_build_object('name', 'mac-' || i, 'remoteManagement', jsonb_build_object('managed', i % 5 <> 0), 'supervised', i % 7 <> 0, 'jamfBinaryVersion', '11.' || k || '.0'),
       NULL, 0, now()
FROM generate_series(1, 40000) i, generate_series(1, 12) k;
INSERT INTO observation_sections (tenant_id, digest, section, body, entry_digests, entry_count, first_seen_at)
SELECT :'tenant', vdg('ea-hist', n::text), 'extension_attributes', NULL, '[]'::jsonb, 150, now()
FROM generate_series(1, 1460000) n;
VACUUM (ANALYZE);
