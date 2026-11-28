-- HOW THIS FILE WAS ACTUALLY RUN (2026-11-28), so the numbers can be traced:
--   days   1-90   daily bump + VACUUM. The bump then read `first_collected_at < _ts`, which skipped spans never changed
--                 since day 0 (their timestamp is the seeding clock): 0.95^90, about 1% of Macs, by day 90 -- expected,
--                 not counted. The day-90 settle bumped them once.
--   Settle "days" are numbered last*1000+500, so the rows they write carry far-future timestamps (and the day-90
--   settle, which still bumped, stamped devices.last_* likewise). No measured query filters on those columns.
--   days  91-166  daily bump of every unchanged current span (`first_run_id IS DISTINCT FROM _run`) + VACUUM.
--   days 167-365  bump + VACUUM every fifth day only (_bump), see the comment at the UPDATE.
--   then sim_rollout.sql: 20 cycles from day 366 (q=0.5, p=0.05), then filler.sql.
--   Checkpoints measured: day 90, 180, 365, after the rollouts, after the filler. Each began with sim_settle + VACUUM (ANALYZE).
-- One simulated daily sweep, written the way record_observation writes (backend/app/observations/ledger.py):
--   changed Mac   -> its changed section's content row, UPDATE old span is_current=false, INSERT new span with previous_id
--   unchanged Mac -> UPDATE of last_observed_at / last_collected_at / observation_count / last_trigger on its current span
--   every Mac     -> devices.last_seen_at stamped
-- _p is the fraction of the fleet whose head digest moves that day. KNOWN_ISSUES.md section 2 plans capacity at 0.05.
-- Which section moved: 65% applications, 15% extension attributes, 10% security (shared bodies), 5% certificates,
-- 5% a group-membership excursion (a new membership list today, back to the original list the next day).
-- Hardware sections never change and membership lists always return to the original, so the fixture's expected
-- counts still hold once the last day's excursions are settled (sim_settle).
\set ON_ERROR_STOP 1

DROP PROCEDURE IF EXISTS sim_settle(int);
DROP PROCEDURE IF EXISTS sim_day(int, float8);

CREATE OR REPLACE PROCEDURE sim_day(_d int, _p float8, _bump boolean DEFAULT true) LANGUAGE plpgsql AS $$
DECLARE
  _ts timestamptz := timestamptz '2025-11-28 03:00:00+00' + make_interval(days => _d);
  _run uuid := gen_random_uuid();
  _tenant uuid := current_setting('looninspect.tenant_id')::uuid;
BEGIN
  CREATE TEMP TABLE chg ON COMMIT DROP AS
  SELECT * FROM (
    SELECT s.id AS old_id, s.mdm_connection_id, s.subject_id, s.label, s.udid, s.serial_number, s.management_id,
           s.contract_version, s.aperture_digest, s.section_digests, o.digest AS orig_digest, o.entry_digests AS orig_entries,
           CASE
             WHEN o.digest IS NOT NULL AND s.section_digests->>'group_memberships' <> o.digest THEN 'gm_return'
             WHEN r.h < _p * 10000 THEN
               CASE WHEN r.pick < 65 THEN 'applications'
                    WHEN r.pick < 80 THEN 'extension_attributes'
                    WHEN r.pick < 90 THEN 'security'
                    WHEN r.pick < 95 THEN CASE WHEN o.digest IS NOT NULL THEN 'gm_detour' ELSE 'applications' END
                    ELSE 'certificates' END
           END AS ev
    FROM observation_spans s
    LEFT JOIN verify_orig o ON o.subject_id = s.subject_id
    CROSS JOIN LATERAL (SELECT (hashint8(s.subject_id::bigint * 1000003 + _d)::bigint & 2147483647) % 10000 AS h,
                               (hashint8(s.subject_id::bigint * 7919 + _d::bigint * 104729)::bigint & 2147483647) % 100 AS pick) r
    WHERE s.is_current AND s.subject_kind = 'computer'
  ) x WHERE ev IS NOT NULL;

  INSERT INTO observation_sections (tenant_id, digest, section, body, entry_digests, entry_count, first_seen_at)
  SELECT _tenant, vdg(ev, subject_id || ':' || _d), ev, NULL,
         CASE ev WHEN 'certificates'
                 THEN jsonb_build_array(vdg('cert', subject_id || ':1:' || _d), vdg('cert', subject_id || ':2'), vdg('cert', subject_id || ':3'), vdg('cert', subject_id || ':4'))
                 ELSE '[]'::jsonb END,   -- applications / extension_attributes: TOASTed in a real ledger; main-heap footprint only
         CASE ev WHEN 'applications' THEN 100 WHEN 'extension_attributes' THEN 150 ELSE 4 END, _ts
  FROM chg WHERE ev IN ('applications', 'extension_attributes', 'certificates');

  INSERT INTO observation_sections (tenant_id, digest, section, body, entry_digests, entry_count, first_seen_at)
  SELECT _tenant, vdg('group_memberships', subject_id || ':' || _d), 'group_memberships', NULL, orig_entries - 0,
         jsonb_array_length(orig_entries) - 1, _ts
  FROM chg WHERE ev = 'gm_detour';

  INSERT INTO observation_sections (tenant_id, digest, section, body, entry_digests, entry_count, first_seen_at)
  SELECT _tenant, vdg('security', 'day:' || (_d % 26)), 'security',
         jsonb_build_object('sipStatus', 'ENABLED', 'gatekeeperStatus', 'APP_STORE_AND_IDENTIFIED_DEVELOPERS', 'xprotectVersion', (6000 + _d % 26)::text,
                            'autoLoginDisabled', true, 'remoteDesktopEnabled', false, 'activationLockEnabled', false, 'firewallEnabled', true,
                            'secureBootLevel', 'FULL_SECURITY', 'externalBootLevel', 'DISALLOW_BOOTING_FROM_EXTERNAL_MEDIA',
                            'bootstrapTokenAllowed', true, 'bootstrapTokenEscrowedStatus', 'ESCROWED'), NULL, 0, _ts
  WHERE EXISTS (SELECT 1 FROM chg WHERE ev = 'security')
  ON CONFLICT ON CONSTRAINT uq_observation_section_digest DO NOTHING;

  UPDATE observation_spans s SET is_current = false FROM chg WHERE s.id = chg.old_id;

  INSERT INTO observation_spans (id, tenant_id, mdm_connection_id, subject_kind, subject_id, label, udid, serial_number, management_id,
      contract_version, aperture_digest, head_digest, section_digests, first_run_id, report_at, first_observed_at, last_observed_at,
      first_collected_at, last_collected_at, observation_count, last_trigger, previous_id, is_current)
  SELECT gen_random_uuid(), _tenant, mdm_connection_id, 'computer', subject_id, label, udid, serial_number, management_id,
      contract_version, aperture_digest, vdg('head', subject_id || ':' || _d),
      section_digests || jsonb_build_object(
          CASE WHEN ev IN ('gm_return', 'gm_detour') THEN 'group_memberships' ELSE ev END,
          CASE ev WHEN 'gm_return' THEN orig_digest
                  WHEN 'gm_detour' THEN vdg('group_memberships', subject_id || ':' || _d)
                  WHEN 'security' THEN vdg('security', 'day:' || (_d % 26))
                  ELSE vdg(ev, subject_id || ':' || _d) END),
      _run, _ts, _ts, _ts, _ts, _ts, 1, 'schedule', old_id, true
  FROM chg;

  -- The unchanged-Mac bump. From day 167 it runs every fifth simulated day only: in one statement it is never a HOT
  -- update (3% were), which production's per-device transactions would mostly get, and it was costing ten index
  -- insertions per Mac per day of simulation time without moving any measured number.
  IF _bump THEN
    UPDATE observation_spans
       SET last_observed_at = _ts, last_collected_at = _ts, observation_count = observation_count + 1, last_trigger = 'schedule'
     WHERE is_current AND subject_kind = 'computer' AND first_run_id IS DISTINCT FROM _run;

    UPDATE devices SET last_seen_at = _ts, last_inventory_at = _ts, last_check_in = _ts;
  END IF;
END $$;

-- Return the Macs still on an excursion to their original membership list (one more ordinary change event for each).
CREATE OR REPLACE PROCEDURE sim_settle(_d int) LANGUAGE plpgsql AS $$
BEGIN
  CALL sim_day(_d, 0.0, false);
END $$;
