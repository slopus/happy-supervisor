# shellcheck shell=bash
# Shared by the token prototypes: a fake node token in a root-only private directory, and a
# check that prints whether each step did what the design expects.

STATE=/var/lib/hs-proto
PRIVATE=$STATE/private
TOKEN=nt_prototype_$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
mkdir -p "$PRIVATE"
chmod 700 "$STATE" "$PRIVATE"
printf '{"nodeToken":"%s"}\n' "$TOKEN" >"$PRIVATE/credentials.json"
chmod 600 "$PRIVATE/credentials.json"
export STATE PRIVATE TOKEN

mismatches=0

# check <label> <ok|fail> <command...>: runs the command and compares its outcome.
check() {
  local label=$1 expect=$2 out got mark
  shift 2
  if out=$("$@" 2>&1); then got=ok; else got=fail; fi
  if [ "$got" = "$expect" ]; then mark=PASS; else mark=MISMATCH; mismatches=$((mismatches + 1)); fi
  printf '%-8s %-72s expected %s, got %s\n' "$mark" "$label" "$expect" "$got"
  printf '%s\n' "$out" | grep -v '^$' | tail -n 3 | sed "s/$TOKEN/<TOKEN>/g; s/^/           /"
}

# stolen <file>: the file holds the node token.
stolen() {
  grep -q "$TOKEN" "$1" 2>/dev/null
}

finish() {
  echo
  echo "mismatches: $mismatches"
  [ "$mismatches" = 0 ]
}
