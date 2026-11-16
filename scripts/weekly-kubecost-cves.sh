#!/usr/bin/env bash
# Weekly per-image HIGH/CRITICAL CVE counts for the latest GA and nightly Kubecost charts.
# Writes to out-cves/: {ga,nightly}.{json,md,slack.txt,svg}, report.md (both tables),
# and slack.json (both, as one plain-text message for the Slack workflow trigger).
set -euo pipefail
[[ ${RUNNER_DEBUG:-} == 1 ]] && set -x

rm -rf out-cves && mkdir out-cves

# Run both even if one fails so the artifacts show as much as possible; fail at the end.
rc=0
scripts/kubecost-cves.py --ignore-unfixed --save out-cves -o json >/dev/null || rc=1
scripts/kubecost-cves.py --ignore-unfixed --nightly --save out-cves -o json >/dev/null || rc=1
[[ -f out-cves/ga.md && -f out-cves/nightly.md ]] || { echo "kubecost-cves.py wrote no report" >&2; exit 1; }

cat out-cves/ga.md out-cves/nightly.md > out-cves/report.md

# Workflow Builder triggers take flat string fields and insert them as plain text.
message=$(cat out-cves/ga.slack.txt <(echo) out-cves/nightly.slack.txt)
jq -n --arg workflow "${GITHUB_WORKFLOW:-local}" --arg repo "${GITHUB_REPOSITORY:-local}" \
  --arg runid "${GITHUB_RUN_ID:-}" --arg message "$message" \
  '$ARGS.named' > out-cves/slack.json
exit $rc
