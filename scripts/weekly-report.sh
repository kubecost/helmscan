#!/usr/bin/env bash
# Weekly CVE report for the Kubecost chart. Compares the newest patch of the
# last three minors, e.g. 3.1.8 -> 3.2.4 and 3.2.4 -> 3.3.0.
# Writes to out/: report.md (both comparisons), one JSON per comparison,
# and slack.json (latest comparison only).
set -euo pipefail
# "Re-run with debug logging" in GitHub Actions sets RUNNER_DEBUG=1; trace every command then.
[[ ${RUNNER_DEBUG:-} == 1 ]] && set -x

helm repo add kubecost https://kubecost.github.io/kubecost --force-update >/dev/null

# Stable releases only (drop -rc.N), newest first; keep the first (newest) patch
# of each minor, then the three newest minors.
read -r latest prior older <<<"$(helm search repo kubecost/kubecost --versions -o json \
  | jq -r '.[].version' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | sort -rV \
  | awk -F. '!seen[$1"."$2]++' | head -n3 | xargs)"
echo "Versions: $older -> $prior -> $latest"
[[ -n $older ]] || { echo "need releases from three minors; check the helm search output" >&2; exit 1; }

rm -rf out && mkdir out

# helmscan saves reports under working-files/scans/<name>/ and exits 0 even
# when an image scan fails, so empty that dir first and treat a missing
# report as failure.
compare() {
  rm -rf working-files/scans && mkdir -p working-files/scans
  ./helmscan --compare --report --json "kubecost/kubecost@$1" "kubecost/kubecost@$2"
  local md
  md=$(find working-files/scans -name '*.md' | head -n1)
  [[ -n $md ]] || { echo "helmscan wrote no report for $1 -> $2; see its log above" >&2; exit 1; }
  cat "$md" >> out/report.md
  cp "${md%.md}.json" "out/$1_to_$2.json"
}
compare "$prior" "$latest"
compare "$older" "$prior"

message=$(jq -r --arg title "*Weekly helmscan: kubecost $prior → $latest*" '
  $title,
  (.summary.severity_counts[] | "• \(.severity | ascii_upcase): \(.previous_count) → \(.current_count)"),
  "New CVEs: \(.added_cves | length) • Fixed CVEs: \(.removed_cves | length)"
' "out/${prior}_to_${latest}.json")

# Slack Workflow Builder triggers only accept flat string fields.
jq -n --arg workflow "${GITHUB_WORKFLOW:-local}" --arg run_url "${RUN_URL:-}" --arg message "$message" \
  '$ARGS.named' > out/slack.json
