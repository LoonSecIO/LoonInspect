#!/bin/sh
# usage: simulate.sh <first day> <last day> <p>   (days inclusive; unchanged-Mac bump and VACUUM every fifth day; then settle + VACUUM ANALYZE)
S=$(cd "$(dirname "$0")" && pwd)
TENANT=00000000-0000-0000-0000-000000000002
FIRST=$1; LAST=$2; P=$3
{
  echo "\\set ON_ERROR_STOP 1"
  echo "SET looninspect.tenant_id='$TENANT';"
  d=$FIRST
  while [ $d -le $LAST ]; do
    if [ $((d % 5)) -eq 0 ]; then
      echo "CALL sim_day($d, $P, true);"; echo "VACUUM observation_spans;"; echo "VACUUM devices;"
    else
      echo "CALL sim_day($d, $P, false);"
    fi
    if [ $((d % 20)) -eq 0 ]; then echo "ANALYZE observation_spans; ANALYZE observation_sections; ANALYZE devices;"; fi
    d=$((d + 1))
  done
  echo "CALL sim_settle($((LAST * 1000 + 500)));"
  echo "VACUUM (ANALYZE);"
  echo "\\echo settled and analyzed"
} > "$S/sim-$FIRST-$LAST.psql"
T0=$(date +%s)
docker exec -i verify1002-pg psql -XqAt -U bench_app -d bench < "$S/sim-$FIRST-$LAST.psql" 2>&1 | grep -v "permission denied"
echo "simulated days $FIRST..$LAST at p=$P in $(( $(date +%s) - T0 ))s"
