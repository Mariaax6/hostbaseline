#!/usr/bin/env sh
# Builds (if needed) and runs every bundled example, asserting the documented exit codes.
set -eu
cd "$(dirname "$0")"
[ -f dist/hostbaseline.jar ] || sh build.sh
JAR=dist/hostbaseline.jar
expect() {
  want=$1; shift
  set +e; java -jar "$JAR" "$@" >/dev/null 2>&1; got=$?; set -e
  if [ "$got" -ne "$want" ]; then echo "FAIL: expected exit $want, got $got: $*" >&2; exit 1; fi
  echo "ok   exit $got   $*"
}
expect 1 examples/risky      reports/risky      --baseline examples/hardened
expect 0 examples/hardened   reports/hardened
expect 3 examples/incomplete reports/incomplete
expect 1 examples/router     reports/router-as-workstation
expect 0 examples/router     reports/router     --role router
expect 2 examples/does-not-exist reports/none
echo "Open reports/risky/report.html to inspect the comparison."
