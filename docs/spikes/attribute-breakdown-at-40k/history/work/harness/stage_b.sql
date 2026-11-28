-- Stage B: give the spike's fixture the CURRENT-state shape docs/jamf-observations.md describes, and nothing else.
-- No history yet. psql variables: n (fleet size), tenant.
--
-- What changes relative to the spike's fixture:
--   * every computer span names all fourteen v0 sections (the default sweep, jamf-observations.md section 5) instead of five,
--     and carries label / udid / serial / management id / first_run_id as record_observation writes them;
--   * observation_sections gains the nine missing sections' rows. List sections whose arrays are TOASTed out of line in a
--     real ledger (applications: 100 digests, KNOWN_ISSUES.md section 2 measures 167 B of heap per row) are written with an
--     EMPTY array, so the main-heap footprint is right and 330 MB of TOAST the four queries never read is skipped;
--   * observation_entries gains the other entry kinds (applications, certificates, accounts, profiles, per-Mac EA values);
--   * the two other subject kinds (smart groups, EA definitions) get their current spans;
--   * subject_departures is no longer empty (rows that exclude no Mac: returned Macs, departed groups and definitions).
-- Hardware sections, group-membership sections, group entries, devices and device_extension_attributes are untouched,
-- so the spike's own result check (bench.check_result) still has to pass.
\set ON_ERROR_STOP 1
SELECT set_config('looninspect.tenant_id', :'tenant', false);

CREATE OR REPLACE FUNCTION vdg(sec text, k text) RETURNS text LANGUAGE sql IMMUTABLE PARALLEL SAFE AS
$$ SELECT 'v0:' || encode(sha256(convert_to(sec || ':' || k, 'UTF8')), 'hex') $$;

-- Each observed Mac's original membership section, kept so simulated membership excursions can return to it.
CREATE TABLE verify_orig AS
SELECT s.subject_id, m.digest, m.entry_digests
FROM observation_spans s
JOIN observation_sections m ON m.section = 'group_memberships' AND m.digest = s.section_digests->>'group_memberships'
WHERE s.is_current AND s.subject_kind = 'computer';
ALTER TABLE verify_orig ADD PRIMARY KEY (subject_id);

-- Nine more sections per Mac -------------------------------------------------------------------------------------
INSERT INTO observation_sections (tenant_id, digest, section, body, entry_digests, entry_count, first_seen_at)
SELECT :'tenant', vdg('applications', i::text), 'applications', NULL, '[]'::jsonb, 100, now() FROM generate_series(1, :n) i;

INSERT INTO observation_sections (tenant_id, digest, section, body, entry_digests, entry_count, first_seen_at)
SELECT :'tenant', vdg('certificates', i::text), 'certificates', NULL,
       jsonb_build_array(vdg('cert', i || ':1'), vdg('cert', i || ':2'), vdg('cert', i || ':3'), vdg('cert', i || ':4')), 4, now()
FROM generate_series(1, :n) i;

INSERT INTO observation_sections (tenant_id, digest, section, body, entry_digests, entry_count, first_seen_at)
SELECT :'tenant', vdg('local_user_accounts', i::text), 'local_user_accounts', NULL,
       jsonb_build_array(vdg('lua', i || ':1'), vdg('lua', i || ':2')), 2, now()
FROM generate_series(1, :n) i;

INSERT INTO observation_sections (tenant_id, digest, section, body, entry_digests, entry_count, first_seen_at)
SELECT :'tenant', vdg('user_and_location', i::text), 'user_and_location',
       jsonb_build_object('username', 'user' || i, 'realname', 'Fixture User ' || i, 'email', 'user' || i || '@example.invalid',
                          'position', 'Engineer', 'departmentId', (i % 40)::text, 'buildingId', (i % 8)::text), NULL, 0, now()
FROM generate_series(1, :n) i;

INSERT INTO observation_sections (tenant_id, digest, section, body, entry_digests, entry_count, first_seen_at)
SELECT :'tenant', vdg('disk_encryption', i::text), 'disk_encryption',
       jsonb_build_object('bootPartitionEncryptionDetails', jsonb_build_object('partitionName', 'Macintosh HD', 'partitionFileVault2State', 'ENCRYPTED'),
                          'individualRecoveryKeyValidityStatus', 'VALID', 'institutionalRecoveryKeyPresent', false,
                          'fileVault2Enabled', true, 'fileVault2EnabledUserNames', jsonb_build_array('user' || i)), NULL, 0, now()
FROM generate_series(1, :n) i;

INSERT INTO observation_sections (tenant_id, digest, section, body, entry_digests, entry_count, first_seen_at)
SELECT :'tenant', vdg('purchasing', g::text), 'purchasing',
       jsonb_build_object('purchased', true, 'leased', false, 'poNumber', 'PO-' || g, 'vendor', 'Fixture Vendor', 'poDate', '2025-01-01',
                          'warrantyDate', '2028-01-01', 'lifeExpectancy', 4), NULL, 0, now()
FROM generate_series(0, 1999) g;

INSERT INTO observation_sections (tenant_id, digest, section, body, entry_digests, entry_count, first_seen_at)
SELECT :'tenant', vdg('security', g::text), 'security',
       jsonb_build_object('sipStatus', 'ENABLED', 'gatekeeperStatus', 'APP_STORE_AND_IDENTIFIED_DEVELOPERS', 'xprotectVersion', (5280 + g)::text,
                          'autoLoginDisabled', true, 'remoteDesktopEnabled', false, 'activationLockEnabled', false, 'firewallEnabled', true,
                          'secureBootLevel', 'FULL_SECURITY', 'externalBootLevel', 'DISALLOW_BOOTING_FROM_EXTERNAL_MEDIA',
                          'bootstrapTokenAllowed', true, 'bootstrapTokenEscrowedStatus', 'ESCROWED'), NULL, 0, now()
FROM generate_series(0, 11) g;

INSERT INTO observation_sections (tenant_id, digest, section, body, entry_digests, entry_count, first_seen_at)
SELECT :'tenant', vdg('configuration_profiles', g::text), 'configuration_profiles', NULL,
       (SELECT jsonb_agg(x ORDER BY x) FROM (SELECT vdg('profile', ((g * 7 + k) % 80)::text) AS x FROM generate_series(1, 20) k) t), 20, now()
FROM generate_series(0, 299) g;

INSERT INTO observation_sections (tenant_id, digest, section, body, entry_digests, entry_count, first_seen_at)
SELECT :'tenant', vdg('software_updates', g::text), 'software_updates', NULL,
       jsonb_build_array(vdg('swu', g::text), vdg('swu', (g + 1)::text)), 2, now()
FROM generate_series(0, 9) g;

-- The other entry kinds ---------------------------------------------------------------------------------------------
INSERT INTO observation_entries (tenant_id, digest, kind, body, label, first_seen_at)
SELECT :'tenant', vdg('cert', i || ':' || k), 'certificate',
       jsonb_build_object('commonName', 'mac-' || i || '-' || k, 'expirationDate', '2027-01-01T00:00:00Z', 'serialNumber', md5(i || ':' || k),
                          'sha1Fingerprint', md5(k || ':' || i) || 'abcdef01', 'subjectName', 'CN=mac-' || i), NULL, now()
FROM generate_series(1, :n) i, generate_series(1, 4) k;

INSERT INTO observation_entries (tenant_id, digest, kind, body, label, first_seen_at)
SELECT :'tenant', vdg('lua', i || ':' || k), 'local_user_account',
       jsonb_build_object('uid', (500 + k)::text, 'userGuid', md5('guid' || i || ':' || k), 'username', 'user' || i || '_' || k,
                          'fullName', 'Fixture User ' || i, 'admin', k = 1, 'homeDirectory', '/Users/user' || i || '_' || k), NULL, now()
FROM generate_series(1, :n) i, generate_series(1, 2) k;

INSERT INTO observation_entries (tenant_id, digest, kind, body, label, first_seen_at)
SELECT :'tenant', vdg('app', a::text), 'application',
       jsonb_build_object('name', 'App ' || (a % 5000) || '.app', 'path', '/Applications/App ' || (a % 5000) || '.app',
                          'version', (a / 5000) || '.' || (a % 97) || '.0', 'bundleId', 'invalid.example.app' || (a % 5000), 'macAppStore', false), NULL, now()
FROM generate_series(1, 60000) a;

INSERT INTO observation_entries (tenant_id, digest, kind, body, label, first_seen_at)
SELECT :'tenant', vdg('profile', g::text), 'configuration_profile',
       jsonb_build_object('profileIdentifier', 'invalid.example.profile.' || g, 'removable', false), 'Profile ' || g, now()
FROM generate_series(0, 79) g;

INSERT INTO observation_entries (tenant_id, digest, kind, body, label, first_seen_at)
SELECT :'tenant', vdg('swu', g::text), 'software_update', jsonb_build_object('name', 'macOS Update ' || g, 'version', '26.' || g), NULL, now()
FROM generate_series(0, 10) g;

-- Per-Mac EA answers (a real fleet has EAs whose value is unique to the Mac: last user, asset tag, ...).
INSERT INTO observation_entries (tenant_id, digest, kind, body, label, first_seen_at)
SELECT :'tenant', vdg('ea-unique', i || ':' || k), 'extension_attribute',
       jsonb_build_object('definitionId', (150 + k)::text, 'values', jsonb_build_array('answer-' || i || '-' || k)), 'Unique attribute ' || k, now()
FROM generate_series(1, :n) i, generate_series(1, 2) k;

-- Computer spans: all fourteen digests and the identity columns ------------------------------------------------------
UPDATE observation_spans s SET
  label = 'mac-' || s.subject_id,
  udid = upper(gen_random_uuid()::text),
  serial_number = 'FIXTURE-' || s.subject_id,
  management_id = gen_random_uuid()::text,
  first_run_id = '11111111-1111-4111-8111-111111111111',
  report_at = s.first_observed_at,
  section_digests = s.section_digests || jsonb_build_object(
      'applications', vdg('applications', s.subject_id),
      'certificates', vdg('certificates', s.subject_id),
      'local_user_accounts', vdg('local_user_accounts', s.subject_id),
      'user_and_location', vdg('user_and_location', s.subject_id),
      'disk_encryption', vdg('disk_encryption', s.subject_id),
      'purchasing', vdg('purchasing', (s.subject_id::int % 2000)::text),
      'security', vdg('security', (s.subject_id::int % 12)::text),
      'configuration_profiles', vdg('configuration_profiles', (s.subject_id::int % 300)::text),
      'software_updates', vdg('software_updates', (s.subject_id::int % 10)::text))
WHERE s.subject_kind = 'computer';

-- The other two subject kinds, current spans only -------------------------------------------------------------------
INSERT INTO observation_sections (tenant_id, digest, section, body, entry_digests, entry_count, first_seen_at)
SELECT :'tenant', vdg('group-def', g::text), 'definition',
       jsonb_build_object('name', 'Group ' || g, 'siteId', '-1', 'criteria', jsonb_build_array(jsonb_build_object('name', 'Operating System Version', 'priority', 0, 'andOr', 'and', 'searchType', 'like', 'value', '26.' || (g % 5)))), NULL, 0, now()
FROM generate_series(1, 300) g WHERE g % 2 = 0;
INSERT INTO observation_sections (tenant_id, digest, section, body, entry_digests, entry_count, first_seen_at)
SELECT :'tenant', vdg('ea-def', g::text), 'definition',
       jsonb_build_object('dataType', 'STRING', 'enabled', true, 'inventoryDisplayType', 'GENERAL', 'inputType', 'SCRIPT'), NULL, 0, now()
FROM generate_series(1, 152) g;

INSERT INTO observation_spans (id, tenant_id, mdm_connection_id, subject_kind, subject_id, label, contract_version, aperture_digest, head_digest,
    section_digests, first_run_id, first_observed_at, last_observed_at, first_collected_at, last_collected_at, observation_count, last_trigger, is_current)
SELECT gen_random_uuid(), :'tenant', 1, 'computer_group', g::text, 'Group ' || g, 'v0', (SELECT min(aperture_digest) FROM observation_spans),
       vdg('head-group', g::text), jsonb_build_object('definition', vdg('group-def', g::text)), '11111111-1111-4111-8111-111111111111',
       now(), now(), now(), now(), 1, 'manual', true
FROM generate_series(1, 300) g WHERE g % 2 = 0;
INSERT INTO observation_spans (id, tenant_id, mdm_connection_id, subject_kind, subject_id, label, contract_version, aperture_digest, head_digest,
    section_digests, first_run_id, first_observed_at, last_observed_at, first_collected_at, last_collected_at, observation_count, last_trigger, is_current)
SELECT gen_random_uuid(), :'tenant', 1, 'extension_attribute_definition', g::text, 'Attribute ' || g, 'v0', (SELECT min(aperture_digest) FROM observation_spans),
       vdg('head-ea-def', g::text), jsonb_build_object('definition', vdg('ea-def', g::text)), '11111111-1111-4111-8111-111111111111',
       now(), now(), now(), now(), 1, 'manual', true
FROM generate_series(1, 152) g;

-- Departures that exclude no Mac ----------------------------------------------------------------------------------------
INSERT INTO subject_departures (tenant_id, mdm_connection_id, subject_kind, subject_id, departed_at, returned_at, matched_by, created_at)
SELECT :'tenant', 1, 'computer', (g * 20)::text, timestamptz '2026-06-01 00:00+00', timestamptz '2026-06-03 00:00+00', 'jamfProID', now()
FROM generate_series(1, :n / 20) g;
INSERT INTO subject_departures (tenant_id, mdm_connection_id, subject_kind, subject_id, departed_at, created_at)
SELECT :'tenant', 1, 'computer_group', (300 + g)::text, timestamptz '2026-05-01 00:00+00', now() FROM generate_series(1, 400) g;
INSERT INTO subject_departures (tenant_id, mdm_connection_id, subject_kind, subject_id, departed_at, created_at)
SELECT :'tenant', 1, 'extension_attribute_definition', (200 + g)::text, timestamptz '2026-05-01 00:00+00', now() FROM generate_series(1, 60) g;
