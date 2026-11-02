#!/usr/bin/env bash
# After the hunt: verify the whole demo run; only if every check passes, freeze and save all evidence.
# Usage (WSL):  bash scripts/finish_run.sh [results folder name, default VERIFIED_RUN]
#   RESULTS_ROOT  where the folder is created (default: Windows Documents\SE6014_checklist_results)
#   CHECKER       optional path to the teammate's check_agent1_output.py
cd "$(dirname "$0")/.." || exit 1
export SENTINELHUNT_KIT=${SENTINELHUNT_KIT:-~/se6014-portable/SentinelHunt_ELK_Portable}
RESULTS_ROOT=${RESULTS_ROOT:-/mnt/c/Users/ckung/Documents/SE6014_checklist_results}
CHECKER=${CHECKER:-/mnt/c/Users/ckung/Downloads/SE6014_Demo_Readiness/check_agent1_output.py}
R="$RESULTS_ROOT/${1:-VERIFIED_RUN}"
H=$(basename "$(ls -t reports/hunt-*.md | head -1)" .md)
echo "hunt: $H"
.venv/bin/python scripts/verify_demo_run.py --report reports/$H.json --ledger mcp_server/ledger/$H.jsonl > /tmp/verify.txt
ok=$?
cat /tmp/verify.txt
if [ $ok -ne 0 ]; then echo; echo "NOT FROZEN: fix the FAILs first"; exit 1; fi
mkdir -p "$R/agent2_reports" "$R/agent1_steps"
cp /tmp/verify.txt "$R/VERIFY_all_checks.txt"
cp -r $(ls -td reports/agent1_steps/*bastion-02-auth* | head -3) "$R/agent1_steps/"
.venv/bin/python scripts/freeze_versions.py && cp versions_and_hashes.json "$R/A_versions_and_hashes.json"
cp reports/$H.md reports/$H.json "$R/agent2_reports/"
cp mcp_server/ledger/$H.jsonl "$R/agent2_reports/${H}_queries.jsonl"
if [ -f "$CHECKER" ]; then
  python3 "$CHECKER" --kit "$SENTINELHUNT_KIT" --feed bastion-02-auth --expected 36 --out "$R/B_agent1_output_bastion_feed.json"
fi
echo; echo "FROZEN AND SAVED to $R"
