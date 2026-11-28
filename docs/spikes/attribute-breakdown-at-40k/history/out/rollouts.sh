#!/bin/sh
# usage: rollouts.sh <first day> <cycles> <q> <p>
# each cycle: a short-lived-group day (q of observed Macs get a new membership list), then an ordinary day at p that returns them.
# unchanged-Mac bump and VACUUM once per five cycles.
S=$(cd "$(dirname "$0")" && pwd)
TENANT=00000000-0000-0000-0000-000000000002
FIRST=$1; CYCLES=$2; Q=$3; P=$4
{
  echo "\\set ON_ERROR_STOP 1"
  echo "SET looninspect.tenant_id='$TENANT';"
  c=0; d=$FIRST
  while [ $c -lt $CYCLES ]; do
    echo "CALL sim_rollout_day($d, $Q, false);"
    d=$((d + 1)); c=$((c + 1))
    if [ $((c % 5)) -eq 0 ]; then
      echo "CALL sim_day($d, $P, true);"; echo "VACUUM observation_spans;"; echo "VACUUM devices;"
      echo "ANALYZE observation_spans; ANALYZE observation_sections; ANALYZE devices;"
    else
      echo "CALL sim_day($d, $P, false);"
    fi
    d=$((d + 1))
  done
  echo "CALL sim_settle($((d * 1000 + 500)));"
  echo "VACUUM (ANALYZE);"
  echo "\\echo settled and analyzed; next free day $d"
} > "$S/rollouts-$FIRST-$CYCLES.psql"
T0=$(date +%s)
docker exec -i verify1002-pg psql -XqAt -U bench_app -d bench < "$S/rollouts-$FIRST-$CYCLES.psql" 2>&1 | grep -v "permission denied"
echo "rollout cycles: $CYCLES from day $FIRST at q=$Q p=$P in $(( $(date +%s) - T0 ))s"
