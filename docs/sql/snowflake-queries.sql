-- Human/BI analyst session, using the read-only role from snowflake-setup.sql.
USE ROLE LOON_ANALYST;
USE WAREHOUSE LOON_READ_WH;
USE DATABASE LOONINSPECT;
USE SCHEMA PUBLIC;
ALTER SESSION SET TIMEZONE = 'UTC';

-- 1. Paste the source event key displayed beside the destination Test result.
SELECT SOURCE_EVENT_KEY, EVENT_TYPE, OCCURRED_AT, LOADED_AT, PAYLOAD
FROM LOON_EVENTS WHERE SOURCE_EVENT_KEY = '<TEST_SOURCE_EVENT_KEY>';

-- 2. Baseline reconciliation: replace with the Re-emit inventory run's jobID.
-- Count distinct device identities, not apps or rows; compare with the run's
-- device count and check Destinations has no unresolved or rejected deliveries.
SELECT COUNT(*) AS EVENTS,
       COUNT(DISTINCT SOURCE_ID, TENANT_ID,
             PAYLOAD:deviceMeta:connectionID::VARCHAR,
             PAYLOAD:deviceMeta:jamfProID::VARCHAR) AS DEVICES
FROM LOON_EVENTS
WHERE EVENT_TYPE = 'device.inventory' AND PAYLOAD:jobID::VARCHAR = '<RE_EMIT_JOB_ID>';

-- 3. Latest known OS/build. An absent build/date is unknown evidence.
SELECT SOURCE_ID, TENANT_ID, CONNECTION_ID, DEVICE_ID, HOST_NAME,
       OS_VERSION, OS_BUILD, OS_SECTION_OBSERVED, OBSERVED_AT, EVENT_OCCURRED_AT, LOADED_AT, OBSERVATION_DATE_KNOWN
FROM LOON_MAC_OS_LATEST ORDER BY SOURCE_ID, TENANT_ID, CONNECTION_ID, DEVICE_ID;

-- 4. Retained dated observations for one Mac, including delayed older arrivals.
-- Replace all four identity values from query 3; Jamf IDs alone are not global.
SELECT OBSERVED_AT, EVENT_OCCURRED_AT, LOADED_AT, OS_VERSION, OS_BUILD
FROM LOON_MAC_OS_OBSERVATIONS
WHERE SOURCE_ID = '<SOURCE_ID>' AND TENANT_ID = '<TENANT_ID>'
  AND CONNECTION_ID = '<CONNECTION_ID>' AND DEVICE_ID = '<DEVICE_ID>'
ORDER BY OBSERVED_AT ASC NULLS LAST, EVENT_OCCURRED_AT;

-- 5. Distinct computers whose tracked OS version changed exactly to 27.2.1
-- during [start, end). Repeated changes count once; 27.2.10 does not match.
-- This counts computers, not people; a user can own several computers.
SELECT COUNT(DISTINCT SOURCE_ID, TENANT_ID,
             PAYLOAD:deviceMeta:connectionID::VARCHAR,
             PAYLOAD:deviceMeta:jamfProID::VARCHAR) AS COMPUTERS_CHANGED
FROM LOON_EVENTS
WHERE EVENT_TYPE = 'device.change'
  AND PAYLOAD:subjectKind::VARCHAR = 'computer'
  AND PAYLOAD:section::VARCHAR = 'operating_system'
  AND PAYLOAD:field::VARCHAR = 'version'
  AND PAYLOAD:new:value::VARCHAR = '27.2.1'
  AND TRY_TO_TIMESTAMP_TZ(PAYLOAD:observedAt::VARCHAR) >= '2026-11-01T00:00:00Z'::TIMESTAMP_TZ
  AND TRY_TO_TIMESTAMP_TZ(PAYLOAD:observedAt::VARCHAR) < '2026-12-01T00:00:00Z'::TIMESTAMP_TZ;

-- 6. Missing source dates, unread OS sections and missing builds stay visible.
SELECT SOURCE_ID, TENANT_ID, CONNECTION_ID, DEVICE_ID, EVENT_OCCURRED_AT, LOADED_AT,
       OBSERVATION_DATE_KNOWN, OS_SECTION_OBSERVED, OS_BUILD
FROM LOON_MAC_OS_OBSERVATIONS
WHERE NOT OBSERVATION_DATE_KNOWN OR NOT OS_SECTION_OBSERVED OR OS_BUILD IS NULL;

-- 7. Sparse-event lag and sweep throughput measurement. This is application-queue-to-
-- commit lag, not the age of Jamf's last device report. Record measured results
-- during the live acceptance exercise; no performance promise is inferred here.
SELECT COUNT(*) AS ROWS_LOADED, MIN(LOADED_AT) AS FIRST_LOAD, MAX(LOADED_AT) AS LAST_LOAD,
       MEDIAN(DATEDIFF('millisecond', QUEUED_AT, LOADED_AT)) AS MEDIAN_QUEUE_LAG_MS,
       MAX(DATEDIFF('millisecond', QUEUED_AT, LOADED_AT)) AS MAX_QUEUE_LAG_MS
FROM LOON_EVENTS WHERE PAYLOAD:jobID::VARCHAR = '<RE_EMIT_JOB_ID>';
